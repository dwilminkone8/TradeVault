// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

interface IWETH {
    function deposit() external payable;
    function withdraw(uint256 wad) external;
}

interface IPermit2 {
    function approve(address token, address spender, uint160 amount, uint48 expiration) external;
}

/// @title  TradeVault
/// @author DW
/// @notice Multi-executor vault that routes swaps through
///         whitelisted router contracts via arbitrary calldata.
/// @dev    Trust model:
///           - owner   : deploys, manages whitelists, withdraws funds, pauses.
///           - executor: whitelisted EOA that triggers swaps and transfers.
///                       Using separate EOAs per executor gives each its own
///                       on-chain nonce, enabling parallel bundle submission.
///         Swaps are executed by forwarding executor-supplied calldata to a
///         whitelisted router address. The router whitelist is the security
///         boundary: only pre-approved, audited contracts may receive calldata
///         and token approvals from the vault.
/// @custom:security-contact security@denayer.io
contract TradeVault is Ownable2Step, Pausable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ═══════════════════════════════════════════════════════════════════
    //  STATE
    // ═══════════════════════════════════════════════════════════════════

    /// @notice Canonical WETH address on this chain. Immutable after deployment.
    address public immutable WETH;

    /// @notice Addresses authorised to call swap, transfer, wrap/unwrap functions.
    mapping(address executor => bool active) public executors;

    /// @notice Router contracts executors may relay arbitrary swap calldata to.
    mapping(address router => bool active) public whitelistedRouters;

    /// @notice Permit2 contracts the vault may interact with for two-step approvals.
    mapping(address permit2 => bool active) public whitelistedPermit2;

    /// @notice Addresses to which executors may push tokens or ETH via transferToken/transferNative.
    mapping(address destination => bool active) public whitelistedDepositAddresses;

    /// @notice Addresses to which executors may send ETH tips (e.g. block.coinbase, relayers).
    mapping(address recipient => bool active) public whitelistedTipRecipients;

    /// @notice Per-router whitelist of 4-byte function selectors executors may invoke via swapViaRouter.
    /// @dev    Fail-closed: a whitelisted router with no whitelisted selector cannot be called at all.
    mapping(address router => mapping(bytes4 selector => bool active)) public whitelistedSelectors;

    // ═══════════════════════════════════════════════════════════════════
    //  ERRORS
    // ═══════════════════════════════════════════════════════════════════

    /// @dev Caller is not a whitelisted executor.
    error NotExecutor();
    /// @dev The transfer destination has not been whitelisted by the owner.
    error DepositAddressNotWhitelisted(address to);
    /// @dev A zero address was supplied where one is not permitted.
    error ZeroAddress();
    /// @dev A protected address (WETH or a Permit2 contract) was submitted as a router.
    error InvalidRouter(address router);
    /// @dev The vault does not hold enough ETH to cover the requested amount.
    error InsufficientBalance();
    /// @dev A low-level ETH transfer returned false.
    error TransferFailed();
    /// @dev The target router has not been whitelisted by the owner.
    error RouterNotWhitelisted(address router);
    /// @dev The target Permit2 contract has not been whitelisted by the owner.
    error Permit2NotWhitelisted(address permit2);
    /// @dev The tip recipient has not been whitelisted by the owner.
    error TipRecipientNotWhitelisted(address to);
    /// @dev A protected address (WETH or a whitelisted router) was submitted as a Permit2 contract.
    error InvalidPermit2(address permit2);
    /// @dev The function selector in the swap calldata is not whitelisted for the target router.
    error SelectorNotWhitelisted(address router, bytes4 selector);
    /// @dev The swap calldata is shorter than the 4-byte function selector.
    error CallDataTooShort();

    // ═══════════════════════════════════════════════════════════════════
    //  EVENTS
    // ═══════════════════════════════════════════════════════════════════

    /// @notice Emitted when an executor is activated or deactivated.
    event ExecutorSet(address indexed account, bool active);
    /// @notice Emitted when a router is whitelisted or de-whitelisted.
    event RouterSet(address indexed router, bool active);
    /// @notice Emitted when a Permit2 contract is whitelisted or de-whitelisted.
    event Permit2Set(address indexed permit2, bool active);
    /// @notice Emitted when a function selector is whitelisted or de-whitelisted for a router.
    event SelectorSet(address indexed router, bytes4 indexed selector, bool active);
    /// @notice Emitted when a deposit destination is whitelisted or de-whitelisted.
    event DepositAddressSet(address indexed account, bool active);
    /// @notice Emitted when a tip recipient is whitelisted or de-whitelisted.
    event TipRecipientSet(address indexed account, bool active);
    /// @notice Emitted when the vault sets an ERC-20 allowance for a router.
    event RouterApproved(address indexed token, address indexed router, uint256 amount);
    /// @notice Emitted when the vault sets a Permit2-mediated allowance for a router.
    event Permit2RouterApproved(
        address indexed permit2,
        address indexed token,
        address indexed router,
        uint160 amount,
        uint48 expiration
    );
    /// @notice Emitted on every successful swap relay.
    event SwapExecuted(address indexed router, uint256 callDataLength);
    /// @notice Emitted when an ETH tip is paid to a whitelisted recipient.
    event Tip(address indexed to, uint256 amount);
    /// @notice Emitted when native ETH is wrapped into WETH.
    event Wrapped(uint256 amount);
    /// @notice Emitted when WETH is unwrapped into native ETH.
    event Unwrapped(uint256 amount);
    /// @notice Emitted when an executor pushes ERC-20 to a whitelisted deposit address.
    event TokenTransferred(address indexed token, address indexed to, uint256 amount);
    /// @notice Emitted when an executor pushes ETH to a whitelisted deposit address.
    event NativeTransferred(address indexed to, uint256 amount);
    /// @notice Emitted when the owner withdraws ERC-20 from the vault.
    event TokenWithdrawn(address indexed token, address indexed to, uint256 amount);
    /// @notice Emitted when the owner withdraws ETH from the vault.
    event NativeWithdrawn(address indexed to, uint256 amount);
    /// @notice Emitted when the owner rescues an ERC-20 to the owner address.
    event TokenRescued(address indexed token, uint256 amount);
    /// @notice Emitted when the owner rescues ETH to the owner address.
    event NativeRescued(uint256 amount);

    // ═══════════════════════════════════════════════════════════════════
    //  MODIFIERS
    // ═══════════════════════════════════════════════════════════════════

    modifier onlyExecutor() {
        if (!executors[msg.sender]) revert NotExecutor();
        _;
    }

    // ═══════════════════════════════════════════════════════════════════
    //  CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════════════

    /// @param _owner Initial owner of the vault (receives admin rights).
    /// @param _weth  Canonical WETH contract on this chain.
    constructor(address _owner, address _weth) Ownable(_owner) {
        if (_weth == address(0)) revert ZeroAddress();
        WETH = _weth;
    }

    /// @dev Prevent accidental permanent lock-out of all owner functions.
    function renounceOwnership() public pure override { revert(); }

    /// @dev Required so WETH9.withdraw() can return ETH to the vault via a low-level
    ///      call. Without this, every unwrap() call would revert.
    receive() external payable {}

    // ═══════════════════════════════════════════════════════════════════
    //  ADMIN — owner-only configuration
    // ═══════════════════════════════════════════════════════════════════

    /// @notice Activate or deactivate a single executor address.
    function setExecutor(address _addr, bool _active) external onlyOwner {
        if (_addr == address(0)) revert ZeroAddress();
        executors[_addr] = _active;
        emit ExecutorSet(_addr, _active);
    }

    /// @notice Add or remove a single router from the whitelist.
    /// @dev    Prevents whitelisting WETH or a Permit2 contract as a router, which
    ///         would let an executor drain the vault's holdings of those tokens.
    function setRouter(address _addr, bool _active) external onlyOwner {
        if (_addr == address(0)) revert ZeroAddress();
        if (_active && (_addr == WETH || whitelistedPermit2[_addr])) revert InvalidRouter(_addr);
        whitelistedRouters[_addr] = _active;
        emit RouterSet(_addr, _active);
    }

    /// @notice Whitelist or remove a function selector a router may be called with via swapViaRouter.
    /// @dev    Defence-in-depth against the universal-calldata relay: only pre-approved operations
    ///         (e.g. a router's swap selector) may be invoked, so executors cannot trigger
    ///         unintended router functionality such as addLiquidity or multicall.
    ///         Selectors are scoped per-router because the same selector can be a harmless swap on
    ///         one router and a dangerous operation on another. When activating, the router must
    ///         already be whitelisted; removal (_active == false) is always permitted so a selector
    ///         can be revoked even after the router itself is de-listed. Selector entries persist
    ///         across router de-listing/re-listing — re-whitelisting a router restores its selectors.
    /// @param _router   Router the selector applies to.
    /// @param _selector 4-byte function selector (e.g. bytes4(keccak256("exactInputSingle(...)"))).
    /// @param _active   True to allow the selector, false to disallow it.
    function setSelector(address _router, bytes4 _selector, bool _active) external onlyOwner {
        if (_active && !whitelistedRouters[_router]) revert RouterNotWhitelisted(_router);
        whitelistedSelectors[_router][_selector] = _active;
        emit SelectorSet(_router, _selector, _active);
    }

    /// @notice Add or remove a Permit2 contract from the whitelist.
    /// @dev    Prevents whitelisting WETH or an already-whitelisted router as Permit2,
    ///         which would let an executor relay calldata to Permit2 via swapViaRouter.
    ///         When deactivating, the vault's outstanding ERC-20 allowances to this
    ///         Permit2 (set to uint256.max by approvePermit2Router) are revoked for each
    ///         token in _tokensToRevoke. Pass every token previously approved to _addr,
    ///         otherwise a de-whitelisted Permit2 retains spending power over vault funds.
    ///         The array is ignored when _active == true.
    /// @param _addr           Permit2 contract address.
    /// @param _active         True to whitelist, false to remove.
    /// @param _tokensToRevoke Tokens whose ERC-20 allowance to _addr is zeroed on removal.
    function setPermit2(address _addr, bool _active, address[] calldata _tokensToRevoke) external onlyOwner {
        if (_addr == address(0)) revert ZeroAddress();
        if (_active && (_addr == WETH || whitelistedRouters[_addr])) revert InvalidPermit2(_addr);
        whitelistedPermit2[_addr] = _active;
        if (!_active) {
            for (uint256 i; i < _tokensToRevoke.length; ++i) {
                IERC20(_tokensToRevoke[i]).forceApprove(_addr, 0);
                emit RouterApproved(_tokensToRevoke[i], _addr, 0);
            }
        }
        emit Permit2Set(_addr, _active);
    }

    /// @notice Add or remove a single address from the deposit whitelist.
    function setDepositAddress(address _addr, bool _active) external onlyOwner {
        if (_addr == address(0)) revert ZeroAddress();
        whitelistedDepositAddresses[_addr] = _active;
        emit DepositAddressSet(_addr, _active);
    }

    /// @notice Add or remove a tip recipient from the whitelist.
    function setTipRecipient(address _addr, bool _active) external onlyOwner {
        if (_addr == address(0)) revert ZeroAddress();
        whitelistedTipRecipients[_addr] = _active;
        emit TipRecipientSet(_addr, _active);
    }

    /// @notice Set the ERC-20 allowance a whitelisted router may spend from the vault.
    /// @dev    Uses forceApprove (handles non-standard tokens). Pass 0 to revoke —
    ///         revocation is always permitted even if the router is no longer whitelisted.
    /// @param _token   ERC-20 token to approve.
    /// @param _router  Whitelisted router to receive the allowance.
    /// @param _amount  Allowance amount (use type(uint256).max for unlimited, 0 to revoke).
    function approveRouter(address _token, address _router, uint256 _amount) external onlyOwner {
        if (_amount > 0 && !whitelistedRouters[_router]) revert RouterNotWhitelisted(_router);
        IERC20(_token).forceApprove(_router, _amount);
        emit RouterApproved(_token, _router, _amount);
    }

    /// @notice Batch-set ERC-20 allowances for multiple token/router pairs.
    /// @dev    Array lengths must match. Entries with _amounts[i] == 0 bypass the
    ///         whitelist check so de-listed routers can always be revoked.
    function approveRouters(
        address[] calldata _tokens,
        address[] calldata _routers,
        uint256[] calldata _amounts
    ) external onlyOwner {
        for (uint256 i; i < _tokens.length; ++i) {
            if (_amounts[i] > 0 && !whitelistedRouters[_routers[i]]) revert RouterNotWhitelisted(_routers[i]);
            IERC20(_tokens[i]).forceApprove(_routers[i], _amounts[i]);
            emit RouterApproved(_tokens[i], _routers[i], _amounts[i]);
        }
    }

    /// @notice Two-step Permit2 approval for routers that pull tokens via Permit2
    ///         (e.g. Uniswap V4 Universal Router).
    ///         Step 1: ERC-20 approve _permit2 to spend _token from the vault.
    ///         Step 2: Tell _permit2 to grant _router an allowance.
    ///         When _amount == 0 (revoking), whitelist checks are skipped and step 1 is
    ///         skipped so only the Permit2 internal allowance is zeroed.
    /// @param _permit2    Whitelisted Permit2 contract address.
    /// @param _token      ERC-20 token to approve.
    /// @param _router     Whitelisted router that will pull via Permit2.
    /// @param _amount     Permit2 allowance (use type(uint160).max for unlimited, 0 to revoke).
    /// @param _expiration Permit2 allowance expiry (use type(uint48).max for no expiry).
    function approvePermit2Router(
        address _permit2,
        address _token,
        address _router,
        uint160 _amount,
        uint48 _expiration
    ) external onlyOwner {
        if (_amount > 0) {
            if (!whitelistedPermit2[_permit2]) revert Permit2NotWhitelisted(_permit2);
            if (!whitelistedRouters[_router]) revert RouterNotWhitelisted(_router);
            IERC20(_token).forceApprove(_permit2, type(uint256).max);
        }
        IPermit2(_permit2).approve(_token, _router, _amount, _expiration);
        emit Permit2RouterApproved(_permit2, _token, _router, _amount, _expiration);
    }

    /// @notice Batch Permit2 approval for multiple token/router pairs.
    /// @dev    Array lengths must match. All entries use the same _permit2 contract.
    ///         Each iteration approves Permit2 on the token (idempotent if already max)
    ///         and sets the Permit2 allowance for the router. Entries with _amounts[i] == 0
    ///         bypass whitelist checks for revocation.
    function approvePermit2Routers(
        address _permit2,
        address[] calldata _tokens,
        address[] calldata _routers,
        uint160[] calldata _amounts,
        uint48[] calldata _expirations
    ) external onlyOwner {
        for (uint256 i; i < _tokens.length; ++i) {
            if (_amounts[i] > 0) {
                if (!whitelistedPermit2[_permit2]) revert Permit2NotWhitelisted(_permit2);
                if (!whitelistedRouters[_routers[i]]) revert RouterNotWhitelisted(_routers[i]);
                IERC20(_tokens[i]).forceApprove(_permit2, type(uint256).max);
            }
            IPermit2(_permit2).approve(_tokens[i], _routers[i], _amounts[i], _expirations[i]);
            emit Permit2RouterApproved(_permit2, _tokens[i], _routers[i], _amounts[i], _expirations[i]);
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  ROUTER RELAY — universal swap via whitelisted router
    //  Compatible with any DEX router (Uniswap V2/V3/V4, 1inch, Paraswap,
    //  OdosRouter, etc.) as long as the address is whitelisted by the owner.
    // ═══════════════════════════════════════════════════════════════════

    /// @notice Execute a swap through a whitelisted router with arbitrary calldata.
    /// @dev    All swap parameters (amounts, slippage, recipient, path) are encoded
    ///         inside _callData. Token allowances are set ahead of time by the owner
    ///         via approveRouter / approveRouters, so no approval logic runs here.
    ///
    ///         The leading 4-byte function selector of _callData is checked against the
    ///         per-router selector whitelist (setSelector / setSelectors). This restricts
    ///         executors to pre-approved router operations (e.g. swaps) and blocks unintended
    ///         functionality such as addLiquidity or multicall. The check is fail-closed:
    ///         a router with no whitelisted selectors cannot be called.
    ///
    ///         Native-token swaps: _value wei is forwarded from the vault's balance to
    ///         the router with the call, so routers that take native ETH as the input
    ///         asset (e.g. swapExactETHForTokens) are fully supported. Pass 0 for pure
    ///         ERC-20 -> ERC-20 swaps. The executor may also attach msg.value to top up
    ///         the vault's ETH balance for the same call.
    ///
    ///         Tips are paid from the vault's ETH balance but are gated by the tip
    ///         recipient whitelist, so a rogue executor cannot redirect vault funds.
    /// @param _router    Whitelisted router address.
    /// @param _value     Native ETH (wei) to forward to the router as swap input (0 if none).
    /// @param _callData  ABI-encoded router call including all swap params and slippage guard.
    /// @param _tipTo     Whitelisted validator / coinbase tip recipient (ignored when _tipAmount == 0).
    /// @param _tipAmount ETH tip paid to _tipTo after the swap (0 to skip tipping).
    function swapViaRouter(
        address _router,
        uint256 _value,
        bytes calldata _callData,
        address payable _tipTo,
        uint256 _tipAmount
    ) external payable onlyExecutor whenNotPaused nonReentrant {
        if (!whitelistedRouters[_router]) revert RouterNotWhitelisted(_router);
        if (_callData.length < 4) revert CallDataTooShort();
        bytes4 selector = bytes4(_callData[:4]);
        if (!whitelistedSelectors[_router][selector]) revert SelectorNotWhitelisted(_router, selector);
        if (address(this).balance < _value) revert InsufficientBalance();

        (bool success, bytes memory returnData) = _router.call{value: _value}(_callData);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(returnData, 32), mload(returnData))
            }
        }
        emit SwapExecuted(_router, _callData.length);

        if (_tipAmount > 0) _tip(_tipTo, _tipAmount);
    }

    // ═══════════════════════════════════════════════════════════════════
    //  WETH HELPERS
    // ═══════════════════════════════════════════════════════════════════

    /// @notice Wrap native ETH held by the vault into WETH.
    function wrap(uint256 _amount) external onlyExecutor whenNotPaused nonReentrant {
        if (address(this).balance < _amount) revert InsufficientBalance();
        IWETH(WETH).deposit{value: _amount}();
        emit Wrapped(_amount);
    }

    /// @notice Unwrap WETH held by the vault into native ETH.
    /// @dev    WETH9.withdraw() returns ETH via a low-level call, which re-enters
    ///         receive(). nonReentrant prevents any further state changes during that
    ///         callback.
    function unwrap(uint256 _amount) external onlyExecutor whenNotPaused nonReentrant {
        IWETH(WETH).withdraw(_amount);
        emit Unwrapped(_amount);
    }

    // ═══════════════════════════════════════════════════════════════════
    //  EXECUTOR TRANSFERS — to whitelisted deposit addresses only
    // ═══════════════════════════════════════════════════════════════════

    /// @notice Transfer an ERC-20 token to a whitelisted deposit address.
    /// @dev    nonReentrant guards against ERC-777 send hooks re-entering the vault.
    function transferToken(address _token, address _to, uint256 _amount) external onlyExecutor whenNotPaused nonReentrant {
        if (!whitelistedDepositAddresses[_to]) revert DepositAddressNotWhitelisted(_to);
        IERC20(_token).safeTransfer(_to, _amount);
        emit TokenTransferred(_token, _to, _amount);
    }

    /// @notice Transfer native ETH to a whitelisted deposit address.
    function transferNative(address payable _to, uint256 _amount) external onlyExecutor whenNotPaused nonReentrant {
        if (!whitelistedDepositAddresses[_to]) revert DepositAddressNotWhitelisted(_to);
        if (address(this).balance < _amount) revert InsufficientBalance();
        (bool sent, ) = _to.call{value: _amount}("");
        if (!sent) revert TransferFailed();
        emit NativeTransferred(_to, _amount);
    }

    // ═══════════════════════════════════════════════════════════════════
    //  WITHDRAWALS — owner only
    // ═══════════════════════════════════════════════════════════════════

    /// @notice Withdraw any ERC-20 token to an arbitrary address.
    /// @dev    nonReentrant guards against ERC-777 send hooks.
    function withdrawToken(address _token, address _to, uint256 _amount) external onlyOwner nonReentrant {
        if (_to == address(0)) revert ZeroAddress();
        IERC20(_token).safeTransfer(_to, _amount);
        emit TokenWithdrawn(_token, _to, _amount);
    }

    /// @notice Withdraw native ETH to an arbitrary address.
    function withdrawNative(address payable _to, uint256 _amount) external onlyOwner nonReentrant {
        if (_to == address(0)) revert ZeroAddress();
        if (address(this).balance < _amount) revert InsufficientBalance();
        (bool sent, ) = _to.call{value: _amount}("");
        if (!sent) revert TransferFailed();
        emit NativeWithdrawn(_to, _amount);
    }

    // ═══════════════════════════════════════════════════════════════════
    //  EMERGENCY
    // ═══════════════════════════════════════════════════════════════════

    /// @notice Pause all executor-facing functions. Owner can still withdraw.
    function pause() external onlyOwner { _pause(); }

    /// @notice Unpause the contract.
    function unpause() external onlyOwner { _unpause(); }

    /// @notice Rescue the vault's entire balance of a stuck ERC-20 to the owner.
    function rescueToken(address _token) external onlyOwner nonReentrant {
        uint256 bal = IERC20(_token).balanceOf(address(this));
        if (bal > 0) {
            IERC20(_token).safeTransfer(owner(), bal);
            emit TokenRescued(_token, bal);
        }
    }

    /// @notice Rescue all native ETH held by the vault to the owner.
    function rescueNative() external onlyOwner nonReentrant {
        uint256 bal = address(this).balance;
        if (bal > 0) {
            (bool sent, ) = payable(owner()).call{value: bal}("");
            if (!sent) revert TransferFailed();
            emit NativeRescued(bal);
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    //  INTERNAL HELPERS
    // ═══════════════════════════════════════════════════════════════════

    /// @dev Send an ETH tip to a whitelisted validator or coinbase address.
    function _tip(address payable _to, uint256 _amount) private {
        if (!whitelistedTipRecipients[_to]) revert TipRecipientNotWhitelisted(_to);
        if (address(this).balance < _amount) revert InsufficientBalance();
        (bool sent, ) = _to.call{value: _amount}("");
        if (!sent) revert TransferFailed();
        emit Tip(_to, _amount);
    }
}

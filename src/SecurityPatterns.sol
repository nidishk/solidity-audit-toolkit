// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ReentrancyGuard
 * @dev Prevents reentrancy attacks
 */
abstract contract ReentrancyGuard {
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;
    uint256 private _status;
    
    error ReentrancyDetected();
    
    constructor() {
        _status = NOT_ENTERED;
    }
    
    modifier nonReentrant() {
        if (_status == ENTERED) revert ReentrancyDetected();
        _status = ENTERED;
        _;
        _status = NOT_ENTERED;
    }
}

/**
 * @title VulnerableVault
 * @dev Intentionally vulnerable for testing audit tools
 */
contract VulnerableVault {
    mapping(address => uint256) public balances;
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] = 0;
    }
}

/**
 * @title SecureVault
 * @dev Fixed version with reentrancy protection
 */
contract SecureVault is ReentrancyGuard {
    mapping(address => uint256) public balances;
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool success,) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}

/**
 * @title OverflowChecker
 * @dev Demonstrates overflow protection
 */
library OverflowChecker {
    error Overflow();
    error Underflow();
    
    function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        if (c < a) revert Overflow();
        return c;
    }
    
    function safeSub(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b > a) revert Underflow();
        return a - b;
    }
    
    function safeMul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) return 0;
        uint256 c = a * b;
        if (c / a != b) revert Overflow();
        return c;
    }
}

/**
 * @title AccessControl
 * @dev Role-based access control
 */
contract AccessControl {
    mapping(bytes32 => mapping(address => bool)) private _roles;
    
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);
    
    error Unauthorized();
    
    constructor() {
        _roles[ADMIN_ROLE][msg.sender] = true;
    }
    
    modifier onlyRole(bytes32 role) {
        if (!hasRole(role, msg.sender)) revert Unauthorized();
        _;
    }
    
    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }
    
    function grantRole(bytes32 role, address account) external onlyRole(ADMIN_ROLE) {
        _roles[role][account] = true;
        emit RoleGranted(role, account);
    }
    
    function revokeRole(bytes32 role, address account) external onlyRole(ADMIN_ROLE) {
        _roles[role][account] = false;
        emit RoleRevoked(role, account);
    }
}

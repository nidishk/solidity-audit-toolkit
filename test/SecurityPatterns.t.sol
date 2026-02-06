// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/SecurityPatterns.sol";

contract ReentrancyAttacker {
    VulnerableVault public vault;
    uint256 public attackCount;
    
    constructor(address _vault) {
        vault = VulnerableVault(_vault);
    }
    
    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw();
    }
    
    receive() external payable {
        if (attackCount < 3 && address(vault).balance >= 1 ether) {
            attackCount++;
            vault.withdraw();
        }
    }
}

contract SecurityPatternsTest is Test {
    VulnerableVault vulnerableVault;
    SecureVault secureVault;
    address alice = address(0x1);
    address bob = address(0x2);

    function setUp() public {
        vulnerableVault = new VulnerableVault();
        secureVault = new SecureVault();
        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);
    }

    function testVulnerableDeposit() public {
        vm.prank(alice);
        vulnerableVault.deposit{value: 1 ether}();
        assertEq(vulnerableVault.balances(alice), 1 ether);
    }

    function testVulnerableWithdraw() public {
        vm.prank(alice);
        vulnerableVault.deposit{value: 1 ether}();
        vm.prank(alice);
        vulnerableVault.withdraw();
        assertEq(vulnerableVault.balances(alice), 0);
        assertEq(alice.balance, 10 ether);
    }

    function testReentrancyAttack() public {
        vm.prank(alice);
        vulnerableVault.deposit{value: 5 ether}();
        
        ReentrancyAttacker attacker = new ReentrancyAttacker(address(vulnerableVault));
        vm.deal(address(attacker), 1 ether);
        attacker.attack{value: 1 ether}();
        
        assertTrue(attacker.attackCount() > 0, "Reentrancy should succeed");
    }

    function testSecureDeposit() public {
        vm.prank(alice);
        secureVault.deposit{value: 1 ether}();
        assertEq(secureVault.balances(alice), 1 ether);
    }

    function testSecureWithdraw() public {
        vm.prank(alice);
        secureVault.deposit{value: 1 ether}();
        vm.prank(alice);
        secureVault.withdraw();
        assertEq(secureVault.balances(alice), 0);
    }
}

contract AccessControlTest is Test {
    AccessControl ac;
    address admin;
    address user = address(0x1);

    function setUp() public {
        admin = address(this);
        ac = new AccessControl();
    }

    function testAdminHasRole() public view {
        assertTrue(ac.hasRole(ac.ADMIN_ROLE(), admin));
    }

    function testGrantRole() public {
        bytes32 role = keccak256("NEW_ROLE");
        ac.grantRole(role, user);
        assertTrue(ac.hasRole(role, user));
    }

    function testRevokeRole() public {
        bytes32 role = keccak256("NEW_ROLE");
        ac.grantRole(role, user);
        ac.revokeRole(role, user);
        assertFalse(ac.hasRole(role, user));
    }

    function testUnauthorizedGrantReverts() public {
        bytes32 role = keccak256("NEW_ROLE");
        vm.prank(user);
        vm.expectRevert(AccessControl.Unauthorized.selector);
        ac.grantRole(role, user);
    }
}

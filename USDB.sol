// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import "./ERC20PresetMinterPauser.sol";

/// @notice USD Balance stable coin
contract USDB is ERC20PresetMinterPauser, Ownable {
    using SafeMath for uint256;
    using Address for address;

    constructor() ERC20PresetMinterPauser("USD Balance", "USDB") {
        // no code
    }

    function recoverTokens(address token) external virtual onlyOwner {
        IERC20(token).transfer(owner(), IERC20(token).balanceOf(address(this)));
    }

    function recoverEth() external virtual onlyOwner {
        payable(owner()).transfer(address(this).balance);
    }

    /// @notice grants minter role to given _account
    /// @param _account minter contract
    function grantRoleMinter(address _account) external {
        grantRole(MINTER_ROLE, _account);
    }

    /// @notice revoke minter role to given _account
    /// @param _account minter contract
    function revokeRoleMinter(address _account) external {
        revokeRole(MINTER_ROLE, _account);
    }

}
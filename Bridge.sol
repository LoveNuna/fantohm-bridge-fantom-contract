// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
pragma experimental ABIEncoderV2;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ECDSA} from "./ECDSA.sol";

interface IBridge {
    function threshold() external view returns (uint256);

    function nonce() external view returns (uint256);

    function signerLength() external view returns (uint256);

    function isSigner(address _candidate) external view returns (bool);

    function verify(bytes32 _hash, bytes[] calldata _signatures)
        external
        view
        returns (bool);
}

contract Bridge is IBridge {
    // whitelist
    uint256 private signerCount = 0;
    mapping(address => bool) private signers;

    // nonce
    uint256 public override threshold = 1;
    uint256 public override nonce = 0;
    uint256 public override bridgeState = 1; 

    // For the initial token
    address[] public tokens = [0x9dAdc36cef5158e35c2cc2b5403e82AEa1E3BdA6, 0x2c2Eb66e59301Ae563b1bFC708303E8a54716E7a];
    uint256[] public init_min_amount = [10**15, 10**15];
    mapping (address => uint256) public tokenWhitelist;

    constructor(
        uint256 _threshold,
        uint256 _nonce,
        address[] memory _signers
    ) public {
        threshold = _threshold;
        nonce = _nonce;
        for (uint256 i = 0; i < _signers.length; i++) {
            signers[_signers[i]] = true;
        }
        for (uint256 i = 0; i < tokens.length; i ++) {
            tokenWhitelist[tokens[i]] = init_min_amount[i];
        }
    }

    event SwapToken(address sender, bytes recipient, uint256 amount, address tokenAddress);
    event Withdraw(address to, uint256 amount, address tokenAddress);
    event ChangeThreshold(uint256 _newThreshold);
    event AddToken(address token, uint256 min_amount, uint count);
    event RemoveToken(address token, uint count);
    event CollectOwerShip(address token, address to);

    // modifier
    modifier withNonce {
        _;
 
        nonce++;
    }

    modifier tokenWhitelisted(address token) {
        require(tokenWhitelist[token] > 0);
        _;
    }

    modifier isTerraAddress(bytes memory _address) {
        uint8 i = 0;
        bytes memory bytesArray = new bytes(5);
        for (i = 0; i < 5 && _address[i] != 0; i++) {
            bytesArray[i] = _address[i];
        }
        require(keccak256(bytesArray) == keccak256(bytes("terra")));
        _;
    }

    function SupportedTokens()
    public
    view
    returns (address[] memory)
    {
        return tokens;
    }

    // gov
    function changeThreshold(uint256 _newThreshold, bytes[] memory _signatures)
        public
        withNonce
    {
        require(
            verify(
                keccak256(abi.encodePacked(nonce, _newThreshold)),
                _signatures
            ),
            "Minter: invalid signature"
        );
        threshold = _newThreshold;
        emit ChangeThreshold(
            _newThreshold
        );
    }

    function addSigner(address _signer, bytes[] memory _signatures)
        public
        withNonce
    {
        require(
            verify(keccak256(abi.encodePacked(nonce, _signer)), _signatures),
            "Minter: invalid signature"
        );
        signerCount++;
        signers[_signer] = true;
    }

    function removeSigner(address _signer, bytes[] memory _signatures)
        public
        withNonce
    {
        require(
            verify(keccak256(abi.encodePacked(nonce, _signer)), _signatures),
            "Minter: invalid signature"
        );
        signerCount--;
        signers[_signer] = false;
    }

    function addToken(address _tokenAddress, uint256 min_amount, bytes[] memory _signatures)
    public
    withNonce
    {
        require(
            verify(keccak256(abi.encodePacked(nonce, _tokenAddress, min_amount)), _signatures),
            "Minter: invalid signature"
        );
        tokenWhitelist[_tokenAddress] = min_amount;
        tokens.push(_tokenAddress);
        emit AddToken(
            _tokenAddress,
            min_amount,
            tokens.length
        );
    }

    function removeToken(address _tokenAddress, bytes[] memory _signatures)
    public
    withNonce
    {
        require(
            verify(keccak256(abi.encodePacked(nonce, _tokenAddress)), _signatures),
            "Minter: invalid signature"
        );

        delete tokenWhitelist[_tokenAddress];

        for (uint i = 0; i < tokens.length - 1; i++) {
            if (tokens[i] == _tokenAddress) {
                tokens[i] = tokens[tokens.length - 1];
                break;
            }
        }
        tokens.pop();
        emit RemoveToken(
            _tokenAddress,
            tokens.length
        );
    }

    function collectOwnership(
        address _token,
        address _to,
        bytes[] memory _signatures
    ) public withNonce {
        require(
            verify(
                keccak256(abi.encodePacked(nonce, _token, _to)),
                _signatures
            ),
            "Minter: invalid signature"
        );
        Ownable(_token).transferOwnership(_to);
        emit CollectOwerShip(
            _token,
            _to
        );
    }

    /*
    * Send funds to multisig account, and emit a SwapToken event for emission to the Terra Network
    *
    * @param _recipient: The intended recipient's Terra Network address.
    * @param _amount: The amount of ENG tokens to be itemized.
    */

    function swapToken(bytes memory _recipient, uint256 _amount, address _tokenAddress)
    public
    tokenWhitelisted(_tokenAddress)
    isTerraAddress(_recipient)
    {
        ERC20 token = ERC20(_tokenAddress);

        require(_amount >= tokenWhitelist[_tokenAddress], "Require transfer greater than minimum");

        token.transferFrom(msg.sender, address(this), _amount);
        // token.approve(address(this), 0);

        emit SwapToken(
            msg.sender,
            _recipient,
            _amount,
            _tokenAddress
        );
    }

    function withdraw(address tokenAddress, address to, uint256 amount, bytes memory terraTxHash, bytes[] memory _signatures) 
    public
    tokenWhitelisted(tokenAddress)
    withNonce
    {
        require(
            verify(
                keccak256(abi.encodePacked(nonce, tokenAddress, to, amount, terraTxHash)),
                _signatures
            ),
            "Minter: invalid signature"
        );
        ERC20(tokenAddress).transfer(to, amount);
        emit Withdraw(
            to,
            amount,
            tokenAddress
        );
    }

    function tokenAllownce(address owner, address spender, address _tokenAddress) public view returns (uint256){
        ERC20 token = ERC20(_tokenAddress);
        return token.allowance(owner,  spender);
    }

    function abiEeccak256EncodePacked(uint256 non, address _token, address _to, uint256 _amount, bytes32 _txHash) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(non, _token, _to, _amount, _txHash)
        );
    }

    function abiEncodePacked(uint256 non, address _token, address _to, uint256 _amount, bytes32 _txHash) public pure returns (bytes memory) {
        return abi.encodePacked(non, _token, _to, _amount, _txHash);
    }

    function ECDSAtoEthSignedMessageHash(bytes32 _hash) public pure returns (bytes32) {
        bytes32 h = ECDSA.toEthSignedMessageHash(_hash);
        return h;
    }

    function ECDSArecover(bytes32 hash, bytes memory signature) public pure returns (address) {
        address currentSigner = ECDSA.recover(hash, signature);
        return currentSigner;
    }

    // view
    function signerLength() public override view returns (uint256) {
        return signerCount;
    }

    function isSigner(address _candidate) public override view returns (bool) {
        return signers[_candidate];
    }

    function verify(bytes32 _hash, bytes[] memory _signatures)
        public
        override
        view
        returns (bool)
    {
        bytes32 h = ECDSA.toEthSignedMessageHash(_hash);
        address lastSigner = address(0x0);
        address currentSigner;

        for (uint256 i = 0; i < _signatures.length; i++) {
            currentSigner = ECDSA.recover(h, _signatures[i]);

            if (currentSigner <= lastSigner) {
                return false;
            }
            if (!signers[currentSigner]) {
                return false;
            }
            lastSigner = currentSigner;
        }

        if (_signatures.length < threshold) {
            return false;
        }

        return true;
    }
}
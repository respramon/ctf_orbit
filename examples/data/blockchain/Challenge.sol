// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Challenge {
    address public owner;
    string public hint = "ORBIT{solidity_hint}";
    constructor() { owner = msg.sender; }
    function check() external view returns (bool) { return tx.origin == owner; }
}

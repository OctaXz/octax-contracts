pragma solidity 0.6.12;

import "@openzeppelin/contracts/math/SafeMath.sol";
import "./libs/IBEP20.sol";
import "./libs/SafeBEP20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import "./OctaX.sol";

// MasterChef is the master of OctaX. He can make OctaX and he is a fair guy.
// Note that it's ownable and the owner wields tremendous power. The ownership
// will be transferred to a governance smart contract once OctaX is sufficiently
// distributed and the community can show to govern itself.
// Have fun reading it. Hopefully it's bug-free. God bless.
contract MasterChef is Ownable, ReentrancyGuard {
    using SafeMath for uint256;
    using SafeBEP20 for IBEP20;

    // Info of each user.
    struct UserInfo {
        uint256 amount; // How many LP tokens the user has provided.
        uint256 rewardDebt; // Reward debt. See explanation below.
        uint256 rewardGoldDebt;
        uint256 lastBlcokWithdrawal;
        // We do some fancy math here. Basically, any point in time, the amount of OctaXs
        // entitled to a user but is pending to be distributed is:
        //
        //   pending reward = (user.amount * pool.accOctaXPerShare) - user.rewardDebt
        //
        // Whenever a user deposits or withdraws LP tokens to a pool. Here's what happens:
        //   1. The pool's `accOctaXPerShare` (and `lastRewardBlock`) gets updated.
        //   2. User receives the pending reward sent to his/her address.
        //   3. User's `amount` gets updated.
        //   4. User's `rewardDebt` gets updated.
    }
    struct PartnerInfo {
        address partnerAddress;
        bool isRegister;
        uint256 totalChildPartner;
    }

    // Info of each pool.
    struct PoolInfo {
        IBEP20 lpToken; // Address of LP token contract.
        uint256 allocPoint; // How many allocation points assigned to this pool. OctaXs to distribute per block.
        uint256 lastRewardBlock; // Last block number that OctaXs distribution occurs.
        uint256 accOctaXPerShare; // Accumulated OctaXs per share, times 1e12. See below.
        uint16 depositFeeBP; // Deposit fee in basis points
    }
    // The OctaX TOKEN!
    OctaX public OctaXToken;
    // Dev address.
    address public devaddr;
    // OctaX tokens created per block.
    // Having block every x day.
    uint256 public OctaXPerBlock;

    uint256 public OctaXPerBlockStartValue;

    // Bonus muliplier for early OctaX makers.
    uint256 public constant BONUS_MULTIPLIER = 1;
    // Deposit burn address
    address public burnAddress;
    uint256 public WithdrawalBurnFeePercent;
    uint256 public WithdrawalFeeToRefPercent;
    uint256 public WithdrawalFeeToBurnAddresPercent;
    uint256 public WithdrawalFeeToBurnSupplyPercent;
    address public constant BurnSupplyAddress =
        0x5555500000000000005555500000000000055555;
    uint256 public constant BlockHavingDay = 15; //Having Every XX Day
    uint256 public constant BlockPerDay = 28800; //AVG
    uint256 public LockDayWithdraw = 1; //Withdraw
    uint256 private constant PercentValue = 10000;
    // Info of each pool.
    PoolInfo[] public poolInfo;

    // Info of each user that stakes LP tokens.
    mapping(uint256 => mapping(address => UserInfo)) public userInfo;
    // Total allocation points. Must be the sum of all allocation points in all pools.
    uint256 public totalAllocPoint = 0;
    // The block number when OctaX mining starts.
    uint256 public startBlock;

    uint256 public referralFee;
    mapping(address => PartnerInfo) public partnerInfo;

    event Deposit(address indexed user, uint256 indexed pid, uint256 amount);
    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);
    event EmergencyWithdraw(
        address indexed user,
        uint256 indexed pid,
        uint256 amount
    );
    event SetNewOwnerTokenAddress(
        address indexed user,
        address indexed newAddress
    );
    event SetBurnAddress(address indexed user, address indexed newAddress);
    event SetDevAddress(address indexed user, address indexed newAddress);
    event UpdateEmissionRate(address indexed user, uint256 goosePerBlock);
    event SetLockDayWithdraw(uint256 day);
    event SetReferralPartnershipAddress(
        address indexed user,
        address indexed referralAddress
    );

    constructor(
        OctaX _OctaX,
        address _devaddr,
        address _feeAddress,
        uint256 _OctaXPerBlock,
        uint256 _startBlock,
        uint256 _feePartnership,
        uint256 _feeWithdrawalForBurn,
        uint256 _feeWithdrawalFeeToRefPercent,
        uint256 _feeWithdrawalFeeToBurnAddresPercent,
        uint256 _feeWithdrawalFeeToBurnSupplyPercent
    ) public {
        OctaXToken = _OctaX;
        devaddr = _devaddr;
        burnAddress = _feeAddress;
        OctaXPerBlock = _OctaXPerBlock;
        OctaXPerBlockStartValue = _OctaXPerBlock;

        if (block.number > _startBlock) {
            startBlock = block.number;
        } else {
            startBlock = _startBlock;
        }
        referralFee = _feePartnership;
        WithdrawalBurnFeePercent = _feeWithdrawalForBurn;
        WithdrawalFeeToRefPercent = _feeWithdrawalFeeToRefPercent;
        WithdrawalFeeToBurnAddresPercent = _feeWithdrawalFeeToBurnAddresPercent;
        WithdrawalFeeToBurnSupplyPercent = _feeWithdrawalFeeToBurnSupplyPercent;
    }

    function updateBlockPerBlock() internal {
        uint256 currentBlock = block.number.sub(startBlock);
        if (currentBlock > 0) {
            uint256 moveDay = currentBlock.div(BlockPerDay);
            if (moveDay > 0) {
                uint256 hv = moveDay.div(BlockHavingDay);
                if (hv > 0) {
                    uint256 outHv = OctaXPerBlockStartValue.div(hv.add(1));
                    OctaXPerBlock = outHv;
                }
            }
        }
    }

    function getMoveDay() external view returns (uint256) {
        uint256 currentBlock = block.number - startBlock;
        uint256 moveDay = currentBlock.div(BlockPerDay);
        return moveDay;
    }

    //Implement for partner referral
    function registerPartner(address _partnerAddress) public {
        PartnerInfo storage partner = partnerInfo[msg.sender];
        require(
            msg.sender != _partnerAddress,
            "Partnership must have different addresses"
        );
        require(partner.isRegister != true, "partnership has been registed!");
        require(_partnerAddress == address(_partnerAddress), "Invalid address");
        partner.partnerAddress = _partnerAddress;
        partner.isRegister = true;
        emit SetReferralPartnershipAddress(msg.sender, _partnerAddress);
    }

    function poolLength() external view returns (uint256) {
        return poolInfo.length;
    }

    mapping(IBEP20 => bool) public poolExistence;
    modifier nonDuplicated(IBEP20 _lpToken) {
        require(poolExistence[_lpToken] == false, "nonDuplicated: duplicated");
        _;
    }

    // Add a new lp to the pool. Can only be called by the owner.
    function add(
        uint256 _allocPoint,
        IBEP20 _lpToken,
        uint16 _depositFeeBP,
        bool _withUpdate
    ) public onlyOwner nonDuplicated(_lpToken) {
        require(
            _depositFeeBP <= PercentValue,
            "add: invalid deposit fee basis points"
        );
        if (_withUpdate) {
            massUpdatePools();
        }
        uint256 lastRewardBlock =
            block.number > startBlock ? block.number : startBlock;
        totalAllocPoint = totalAllocPoint.add(_allocPoint);
        poolExistence[_lpToken] = true;
        poolInfo.push(
            PoolInfo({
                lpToken: _lpToken,
                allocPoint: _allocPoint,
                lastRewardBlock: lastRewardBlock,
                accOctaXPerShare: 0,
                depositFeeBP: _depositFeeBP
            })
        );
    }

    // Update the given pool's OctaX allocation point and deposit fee. Can only be called by the owner.
    function set(
        uint256 _pid,
        uint256 _allocPoint,
        uint16 _depositFeeBP,
        bool _withUpdate
    ) public onlyOwner {
        require(
            _depositFeeBP <= PercentValue,
            "set: invalid deposit fee basis points"
        );
        if (_withUpdate) {
            massUpdatePools();
        }
        totalAllocPoint = totalAllocPoint.sub(poolInfo[_pid].allocPoint).add(
            _allocPoint
        );
        poolInfo[_pid].allocPoint = _allocPoint;
        poolInfo[_pid].depositFeeBP = _depositFeeBP;
    }

    // Return reward multiplier over the given _from to _to block.
    function getMultiplier(uint256 _from, uint256 _to)
        public
        view
        returns (uint256)
    {
        return _to.sub(_from).mul(BONUS_MULTIPLIER);
    }

    // View function to see pending OctaXs on frontend.
    function pendingOctaX(uint256 _pid, address _user)
        external
        view
        returns (uint256)
    {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][_user];
        uint256 accOctaXPerShare = pool.accOctaXPerShare;
        uint256 lpSupply = pool.lpToken.balanceOf(address(this));
        if (block.number > pool.lastRewardBlock && lpSupply != 0) {
            uint256 multiplier =
                getMultiplier(pool.lastRewardBlock, block.number);
            uint256 OctaXReward =
                multiplier.mul(OctaXPerBlock).mul(pool.allocPoint).div(
                    totalAllocPoint
                );
            accOctaXPerShare = accOctaXPerShare.add(
                OctaXReward.mul(1e12).div(lpSupply)
            );
        }
        return
            user.amount.mul(accOctaXPerShare).div(1e12).sub(
                user.rewardDebt
            );
    }

    // Update reward variables for all pools. Be careful of gas spending!
    function massUpdatePools() public {
        uint256 length = poolInfo.length;
        for (uint256 pid = 0; pid < length; ++pid) {
            updatePool(pid);
        }
    }

    function thisAddress() public view returns (address) {
        return address(this);
    }

    function withdrawLastLockDay(uint256 _pid, address _user)
        public
        view
        returns (uint256)
    {
        UserInfo storage user = userInfo[_pid][_user];
        uint256 _currentBlock = block.number;
        uint256 _lastBlock = user.lastBlcokWithdrawal;
        if (_currentBlock > _lastBlock) {
            uint256 moveBlockSub = _currentBlock.sub(_lastBlock);
            if (moveBlockSub > 0) {
                uint256 moveDayWd = moveBlockSub.div(BlockPerDay);
                if (LockDayWithdraw > moveDayWd) {
                    uint256 moveDayDef = LockDayWithdraw.sub(moveDayWd);
                    return moveDayDef;
                } else {
                    return 0;
                }
            }
        }
        return LockDayWithdraw;
    }

    // Update reward variables of the given pool to be up-to-date.
    function updatePool(uint256 _pid) public {
        updateBlockPerBlock();
        PoolInfo storage pool = poolInfo[_pid];
        if (block.number <= pool.lastRewardBlock) {
            return;
        }
        uint256 lpSupply = pool.lpToken.balanceOf(address(this));
        if (lpSupply == 0 || pool.allocPoint == 0) {
            pool.lastRewardBlock = block.number;
            return;
        }
        uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);
        uint256 OctaXReward =
            multiplier.mul(OctaXPerBlock).mul(pool.allocPoint).div(
                totalAllocPoint
            );
        OctaXToken.mint(devaddr, OctaXReward.div(10));
        OctaXToken.mint(address(this), OctaXReward);
        pool.accOctaXPerShare = pool.accOctaXPerShare.add(
            OctaXReward.mul(1e12).div(lpSupply)
        );
        pool.lastRewardBlock = block.number;
    }

    // Deposit LP tokens to MasterChef for OctaX allocation.
    function deposit(uint256 _pid, uint256 _amount) public nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        PartnerInfo storage partnerData = partnerInfo[msg.sender];
        updatePool(_pid);
        if (user.amount > 0) {
            uint256 pending =
                user.amount.mul(pool.accOctaXPerShare).div(1e12).sub(
                    user.rewardDebt
                );
            if (pending > 0) {
                uint256 withdrawFeeBurn =
                    pending.mul(WithdrawalBurnFeePercent).div(PercentValue);
                if (referralFee > 0 && partnerData.isRegister) {
                    uint256 withdrawalFeeToRefAmount =
                        withdrawFeeBurn.mul(WithdrawalFeeToRefPercent).div(
                            PercentValue
                        );
                    uint256 withdrawalBalanceOut =
                        withdrawFeeBurn.sub(withdrawalFeeToRefAmount);
                    uint256 withdrawalFeeToBurnSupplyAmount =
                        withdrawalBalanceOut
                            .mul(WithdrawalFeeToBurnSupplyPercent)
                            .div(PercentValue);
                    uint256 withdrawalFeeToBurnAddresAmount =
                        withdrawalBalanceOut.sub(
                            withdrawalFeeToBurnSupplyAmount
                        );
                    if (withdrawalFeeToBurnSupplyAmount > 0) {
                        safeOctaXTransfer(
                            BurnSupplyAddress,
                            withdrawalFeeToBurnSupplyAmount
                        );
                    }
                    if (withdrawalFeeToBurnAddresAmount > 0) {
                        safeOctaXTransfer(
                            burnAddress,
                            withdrawalFeeToBurnAddresAmount
                        );
                    }
                    if (withdrawalFeeToRefAmount > 0) {
                        safeOctaXTransfer(
                            partnerData.partnerAddress,
                            withdrawalFeeToRefAmount
                        );
                    }
                } else {
                    uint256 feeBurnSupplyAmount =
                        withdrawFeeBurn
                            .mul(WithdrawalFeeToBurnSupplyPercent)
                            .div(PercentValue);
                    uint256 feeBurnAddressAmount =
                        withdrawFeeBurn.sub(feeBurnSupplyAmount);
                    if (feeBurnAddressAmount > 0) {
                        safeOctaXTransfer(
                            burnAddress,
                            feeBurnAddressAmount
                        );
                    }
                    if (feeBurnSupplyAmount > 0) {
                        safeOctaXTransfer(
                            BurnSupplyAddress,
                            feeBurnSupplyAmount
                        );
                    }
                }
                uint256 pendingOut = pending.sub(withdrawFeeBurn);
                if (pendingOut > 0) {
                    safeOctaXTransfer(address(msg.sender), pendingOut);
                }
            }
        }
        if (_amount > 0) {
            pool.lpToken.safeTransferFrom(
                address(msg.sender),
                address(this),
                _amount
            );
            if (pool.depositFeeBP > 0) {
                uint256 depositFee =
                    _amount.mul(pool.depositFeeBP).div(PercentValue);
                if (referralFee > 0 && partnerData.isRegister) {
                    uint256 depositFeePartner =
                        depositFee.mul(referralFee).div(PercentValue);
                    uint256 blDepositFee = depositFee.sub(depositFeePartner);
                    pool.lpToken.safeTransfer(
                        partnerData.partnerAddress,
                        depositFeePartner
                    );
                    pool.lpToken.safeTransfer(burnAddress, blDepositFee);
                } else {
                    pool.lpToken.safeTransfer(burnAddress, depositFee);
                }
                user.amount = user.amount.add(_amount).sub(depositFee);
            } else {
                user.amount = user.amount.add(_amount);
            }
        }
        user.rewardDebt = user.amount.mul(pool.accOctaXPerShare).div(1e12);
        user.lastBlcokWithdrawal = block.number;
        emit Deposit(msg.sender, _pid, _amount);
    }

    // Withdraw LP tokens from MasterChef.
    function withdraw(uint256 _pid, uint256 _amount) public nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        PartnerInfo storage partnerData = partnerInfo[msg.sender];
        require(user.amount >= _amount, "withdraw: not good");

        bool canWithdraw = false;
        uint256 _currentBlock = block.number;
        uint256 _lastBlock = user.lastBlcokWithdrawal;
        if (_currentBlock > _lastBlock) {
            uint256 moveBlockSub = _currentBlock.sub(_lastBlock);
            if (moveBlockSub > 0) {
                uint256 moveDayWd = moveBlockSub.div(BlockPerDay);
                if (LockDayWithdraw <= moveDayWd) {
                    canWithdraw = true;
                }
            }
        }
        require(canWithdraw, "withdraw :time lock");
        updatePool(_pid);
        //Check timeout
        uint256 pending =
            user.amount.mul(pool.accOctaXPerShare).div(1e12).sub(
                user.rewardDebt
            );
        if (pending > 0) {
            uint256 withdrawFeeBurn =
                pending.mul(WithdrawalBurnFeePercent).div(PercentValue);
            if (referralFee > 0 && partnerData.isRegister) {
                uint256 withdrawalFeeToRefAmount =
                    withdrawFeeBurn.mul(WithdrawalFeeToRefPercent).div(
                        PercentValue
                    );
                uint256 withdrawalBalanceOut =
                    withdrawFeeBurn.sub(withdrawalFeeToRefAmount);
                uint256 withdrawalFeeToBurnSupplyAmount =
                    withdrawalBalanceOut
                        .mul(WithdrawalFeeToBurnSupplyPercent)
                        .div(PercentValue);
                uint256 withdrawalFeeToBurnAddresAmount =
                    withdrawalBalanceOut.sub(withdrawalFeeToBurnSupplyAmount);
                if (withdrawalFeeToBurnSupplyAmount > 0) {
                    safeOctaXTransfer(
                        BurnSupplyAddress,
                        withdrawalFeeToBurnSupplyAmount
                    );
                }
                if (withdrawalFeeToBurnAddresAmount > 0) {
                    safeOctaXTransfer(
                        burnAddress,
                        withdrawalFeeToBurnAddresAmount
                    );
                }
                if (withdrawalFeeToRefAmount > 0) {
                    safeOctaXTransfer(
                        partnerData.partnerAddress,
                        withdrawalFeeToRefAmount
                    );
                }
            } else {
                uint256 feeBurnSupplyAmount =
                    withdrawFeeBurn.mul(WithdrawalFeeToBurnSupplyPercent).div(
                        PercentValue
                    );
                uint256 feeBurnAddressAmount =
                    withdrawFeeBurn.sub(feeBurnSupplyAmount);
                if (feeBurnAddressAmount > 0) {
                    safeOctaXTransfer(burnAddress, feeBurnAddressAmount);
                }
                if (feeBurnSupplyAmount > 0) {
                    safeOctaXTransfer(
                        BurnSupplyAddress,
                        feeBurnSupplyAmount
                    );
                }
            }
            uint256 pendingOut = pending.sub(withdrawFeeBurn);
            if (pendingOut > 0) {
                safeOctaXTransfer(address(msg.sender), pendingOut);
            }
        }
        if (_amount > 0) {
            user.amount = user.amount.sub(_amount);
            pool.lpToken.safeTransfer(address(msg.sender), _amount);
        }
        user.rewardDebt = user.amount.mul(pool.accOctaXPerShare).div(1e12);
        user.lastBlcokWithdrawal = block.number;
        emit Withdraw(msg.sender, _pid, _amount);
    }

    // Withdraw without caring about rewards. EMERGENCY ONLY.
    function emergencyWithdraw(uint256 _pid) public nonReentrant {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];

        bool canWithdraw = false;
        uint256 _currentBlock = block.number;
        uint256 _lastBlock = user.lastBlcokWithdrawal;
        if (_currentBlock > _lastBlock) {
            uint256 moveBlockSub = _currentBlock.sub(_lastBlock);
            if (moveBlockSub > 0) {
                uint256 moveDayWd = moveBlockSub.div(BlockPerDay);
                if (LockDayWithdraw <= moveDayWd) {
                    canWithdraw = true;
                }
            }
        }
        require(canWithdraw, "withdraw :time lock");

        uint256 amount = user.amount;
        user.amount = 0;
        user.rewardDebt = 0;
        pool.lpToken.safeTransfer(address(msg.sender), amount);
        emit EmergencyWithdraw(msg.sender, _pid, amount);
    }

    // Safe OctaX transfer function, just in case if rounding error causes pool to not have enough OctaXs.
    function safeOctaXTransfer(address _to, uint256 _amount) internal {
        uint256 OctaXBal = OctaXToken.balanceOf(address(this));
        bool transferSuccess = false;
        if (_amount > OctaXBal) {
            transferSuccess = OctaXToken.transfer(_to, OctaXBal);
        } else {
            transferSuccess = OctaXToken.transfer(_to, _amount);
        }
        require(transferSuccess, "safeOctaXTransfer: transfer failed");
    }

    // Update dev address by the previous dev.
    function dev(address _devaddr) public {
        require(msg.sender == devaddr, "dev: wut?");
        devaddr = _devaddr;
        emit SetDevAddress(msg.sender, _devaddr);
    }

    function setBurnAddress(address _burnAddress) public {
        require(msg.sender == burnAddress, "setBurnAddress: FORBIDDEN");
        burnAddress = _burnAddress;
        emit SetBurnAddress(msg.sender, _burnAddress);
    }

    //Pancake has to add hidden dummy pools inorder to alter the emission, here we make it simple and transparent to all.
    function updateEmissionRate(uint256 _OctaXPerBlock) public onlyOwner {
        massUpdatePools();
        OctaXPerBlock = _OctaXPerBlock;
        emit UpdateEmissionRate(msg.sender, _OctaXPerBlock);
    }

    function setLockDayWithdraw(uint256 _lockDay) public onlyOwner {
        LockDayWithdraw = _lockDay;
        emit SetLockDayWithdraw(_lockDay);
    }

    function TokenTransferOwner(address _newOwner) public onlyOwner {
        OctaXToken.transferOwnership(_newOwner);
        emit SetNewOwnerTokenAddress(msg.sender, _newOwner);
    }
}

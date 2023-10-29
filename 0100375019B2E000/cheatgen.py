import sys
sys.path.insert(1,'..\__python__')
from cheatLib import *

################################ START ######################################

# Game Name in English, and then secondary Language, don't ask for emulator
Init('The Mageseeker, A LEAGUE OF LEGENDS STORY' , '《聯盟外傳：狙魔者》', False)

# CharacterPlayerController = GetADRL(AOB('? ? ? ? ? ? ? 91 ? ? ? ? 28 00 80 52 88 DE 03 39 68 1A 40 F9'))
# CharacterPlayerController = 0x5B155C8 v1.0.2
# CharacterPlayerMovement_Type = 5AFA838


DigitalSun_Starblitz_CharacterAnimatorControllerSylas_TypeInfo = [GetADRP(AOB('09 ? ? F9 7F FE 01 A9'))]
# DigitalSun_Starblitz_CharacterControllerSylas_TypeInfo = [0x5AF89E0] # v1.0.2
DigitalSun_Starblitz_CharacterControllerSylas = DigitalSun_Starblitz_CharacterAnimatorControllerSylas_TypeInfo + [0xB8,0,0x20]
DigitalSun_Starblitz_CharacterControllerSylas_OnPlayerDieInTutorialHandler = DigitalSun_Starblitz_CharacterControllerSylas + [0x8]
DigitalSun_Starblitz_CharacterControllerSylas_OnPlayerBecomesVisibleHandler = DigitalSun_Starblitz_CharacterControllerSylas + [0x8]
DigitalSun_Starblitz_CharacterControllerSylas_OnSylasShieldChangeHandler = DigitalSun_Starblitz_CharacterControllerSylas + [0x8]
DigitalSun_Starblitz_CharacterControllerSylas__isPotionBlocked = DigitalSun_Starblitz_CharacterControllerSylas + [0x10]
DigitalSun_Starblitz_CharacterControllerSylas_OnSylasInitializeStatsHandler = DigitalSun_Starblitz_CharacterControllerSylas + [0x10]
DigitalSun_Starblitz_CharacterControllerSylas_OnInventoryInitializeHandler = DigitalSun_Starblitz_CharacterControllerSylas + [0x18]
DigitalSun_Starblitz_CharacterControllerSylas_OnCharacterDamagedHandler = DigitalSun_Starblitz_CharacterControllerSylas + [0x18]
DigitalSun_Starblitz_CharacterControllerSylas_OnCharacterDieHandler = DigitalSun_Starblitz_CharacterControllerSylas + [0x20]
DigitalSun_Starblitz_CharacterControllerSylas_OnCharacterTokeDamageHandler = DigitalSun_Starblitz_CharacterControllerSylas + [0x20]
DigitalSun_Starblitz_CharacterControllerSylas_OnAbnormalStatusAppliedToSylasHandler = DigitalSun_Starblitz_CharacterControllerSylas + [0x28]
DigitalSun_Starblitz_CharacterControllerSylas_OnCharacterRestoreHealthHandler = DigitalSun_Starblitz_CharacterControllerSylas + [0x28]
DigitalSun_Starblitz_CharacterControllerSylas_OnPlayerDataLoadedFromDiskHandler = DigitalSun_Starblitz_CharacterControllerSylas + [0x30]
DigitalSun_Starblitz_CharacterControllerSylas_OnCharacterDamageShieldHandler = DigitalSun_Starblitz_CharacterControllerSylas + [0x30]
DigitalSun_Starblitz_CharacterControllerSylas_OnManaChangedHandler = DigitalSun_Starblitz_CharacterControllerSylas + [0x38]
DigitalSun_Starblitz_CharacterControllerSylas_OnCharacterRestoreShieldHandler = DigitalSun_Starblitz_CharacterControllerSylas + [0x38]
DigitalSun_Starblitz_CharacterControllerSylas_OnCharacterReviveHandler = DigitalSun_Starblitz_CharacterControllerSylas + [0x40]
DigitalSun_Starblitz_CharacterControllerSylas_OnCharacterAddShieldHandler = DigitalSun_Starblitz_CharacterControllerSylas + [0x40]
DigitalSun_Starblitz_CharacterControllerSylas_OnPlayerInitializedHandler = DigitalSun_Starblitz_CharacterControllerSylas + [0x48]
DigitalSun_Starblitz_CharacterControllerSylas_OnCharacterRemoveShieldHandler = DigitalSun_Starblitz_CharacterControllerSylas + [0x48]
DigitalSun_Starblitz_CharacterControllerSylas_OnCharacterDamageGuardHandler = DigitalSun_Starblitz_CharacterControllerSylas + [0x50]
DigitalSun_Starblitz_CharacterControllerSylas_OnCharacterRestoreGuardHandler = DigitalSun_Starblitz_CharacterControllerSylas + [0x58]
DigitalSun_Starblitz_CharacterControllerSylas_OnCharacterRemovedGuardHandler = DigitalSun_Starblitz_CharacterControllerSylas + [0x60]
DigitalSun_Starblitz_CharacterControllerSylas__characterDataDefault = DigitalSun_Starblitz_CharacterControllerSylas + [0x68]
DigitalSun_Starblitz_CharacterControllerSylas__characterDataInstance = DigitalSun_Starblitz_CharacterControllerSylas + [0x70]
DigitalSun_Starblitz_CharacterControllerSylas__currentAttackData = DigitalSun_Starblitz_CharacterControllerSylas + [0x78]
DigitalSun_Starblitz_CharacterControllerSylas__canvas = DigitalSun_Starblitz_CharacterControllerSylas + [0x80]
DigitalSun_Starblitz_CharacterControllerSylas__animator = DigitalSun_Starblitz_CharacterControllerSylas + [0x88]
DigitalSun_Starblitz_CharacterControllerSylas__transform = DigitalSun_Starblitz_CharacterControllerSylas + [0x90]
DigitalSun_Starblitz_CharacterControllerSylas__rigidbody = DigitalSun_Starblitz_CharacterControllerSylas + [0x98]
DigitalSun_Starblitz_CharacterControllerSylas__abnormalStatusSystem = DigitalSun_Starblitz_CharacterControllerSylas + [0xA0]
DigitalSun_Starblitz_CharacterControllerSylas__feedbackController = DigitalSun_Starblitz_CharacterControllerSylas + [0xA8]
DigitalSun_Starblitz_CharacterControllerSylas__characterFXController = DigitalSun_Starblitz_CharacterControllerSylas + [0xB0]
DigitalSun_Starblitz_CharacterControllerSylas__spriteRenderers = DigitalSun_Starblitz_CharacterControllerSylas + [0xB8]
DigitalSun_Starblitz_CharacterControllerSylas__characterCenter = DigitalSun_Starblitz_CharacterControllerSylas + [0xC0]
DigitalSun_Starblitz_CharacterControllerSylas__hookablePoint = DigitalSun_Starblitz_CharacterControllerSylas + [0xC8]
DigitalSun_Starblitz_CharacterControllerSylas__frameData = DigitalSun_Starblitz_CharacterControllerSylas + [0xD0]
DigitalSun_Starblitz_CharacterControllerSylas__isBlockedFromCutscene = DigitalSun_Starblitz_CharacterControllerSylas + [0x118]
DigitalSun_Starblitz_CharacterControllerSylas__absoluteBlockMovement = DigitalSun_Starblitz_CharacterControllerSylas + [0x119]
DigitalSun_Starblitz_CharacterControllerSylas__absoluteBlockCasting = DigitalSun_Starblitz_CharacterControllerSylas + [0x11A]
DigitalSun_Starblitz_CharacterControllerSylas__absoluteIsRooted = DigitalSun_Starblitz_CharacterControllerSylas + [0x11B]
DigitalSun_Starblitz_CharacterControllerSylas__absoluteIsStunned = DigitalSun_Starblitz_CharacterControllerSylas + [0x11C]
DigitalSun_Starblitz_CharacterControllerSylas__absoluteIsSilenced = DigitalSun_Starblitz_CharacterControllerSylas + [0x11D]
DigitalSun_Starblitz_CharacterControllerSylas__isInvincible = DigitalSun_Starblitz_CharacterControllerSylas + [0x11E]  ##
DigitalSun_Starblitz_CharacterControllerSylas__isInvulnerable = DigitalSun_Starblitz_CharacterControllerSylas + [0x11F]
DigitalSun_Starblitz_CharacterControllerSylas__invulnerableStackIds = DigitalSun_Starblitz_CharacterControllerSylas + [0x120]
DigitalSun_Starblitz_CharacterControllerSylas__assignedEnemyArea = DigitalSun_Starblitz_CharacterControllerSylas + [0x128]
DigitalSun_Starblitz_CharacterControllerSylas__assignedEnemyActivationArea = DigitalSun_Starblitz_CharacterControllerSylas + [0x130]
DigitalSun_Starblitz_CharacterControllerSylas__abilitySpawnPoint = DigitalSun_Starblitz_CharacterControllerSylas + [0x138]
DigitalSun_Starblitz_CharacterControllerSylas__soundConstants = DigitalSun_Starblitz_CharacterControllerSylas + [0x140]
DigitalSun_Starblitz_CharacterControllerSylas__originalSortingOrders = DigitalSun_Starblitz_CharacterControllerSylas + [0x148]
DigitalSun_Starblitz_CharacterControllerSylas__originalSortingGroupOrders = DigitalSun_Starblitz_CharacterControllerSylas + [0x150]
DigitalSun_Starblitz_CharacterControllerSylas_OnCharacterDealtDamageHandler = DigitalSun_Starblitz_CharacterControllerSylas + [0x158]
DigitalSun_Starblitz_CharacterControllerSylas_sylasStatsLevel = DigitalSun_Starblitz_CharacterControllerSylas + [0x160]
DigitalSun_Starblitz_CharacterControllerSylas__characterCombat = DigitalSun_Starblitz_CharacterControllerSylas + [0x168]
DigitalSun_Starblitz_CharacterControllerSylas__characterMovement = DigitalSun_Starblitz_CharacterControllerSylas + [0x170]
DigitalSun_Starblitz_CharacterControllerSylas__characterAim = DigitalSun_Starblitz_CharacterControllerSylas + [0x178]
DigitalSun_Starblitz_CharacterControllerSylas__characterCombatAim = DigitalSun_Starblitz_CharacterControllerSylas + [0x180]
DigitalSun_Starblitz_CharacterControllerSylas__playerController = DigitalSun_Starblitz_CharacterControllerSylas + [0x188]
DigitalSun_Starblitz_CharacterControllerSylas__cameraTargetDeath = DigitalSun_Starblitz_CharacterControllerSylas + [0x190]
DigitalSun_Starblitz_CharacterControllerSylas__runeEquipment = DigitalSun_Starblitz_CharacterControllerSylas + [0x198]
DigitalSun_Starblitz_CharacterControllerSylas__maxMana = DigitalSun_Starblitz_CharacterControllerSylas + [0x1A0]
DigitalSun_Starblitz_CharacterControllerSylas__currentMana = DigitalSun_Starblitz_CharacterControllerSylas + [0x1A4]
DigitalSun_Starblitz_CharacterControllerSylas__dialoguePoint = DigitalSun_Starblitz_CharacterControllerSylas + [0x1A8]
DigitalSun_Starblitz_CharacterControllerSylas__inventory = DigitalSun_Starblitz_CharacterControllerSylas + [0x1B0]
DigitalSun_Starblitz_CharacterControllerSylas__inventoryInstance = DigitalSun_Starblitz_CharacterControllerSylas + [0x1B8]
DigitalSun_Starblitz_CharacterControllerSylas__deathSnapshot = DigitalSun_Starblitz_CharacterControllerSylas + [0x1C0]
DigitalSun_Starblitz_CharacterControllerSylas__inputBuffer = DigitalSun_Starblitz_CharacterControllerSylas + [0x1C8]
DigitalSun_Starblitz_CharacterControllerSylas__canReviveFromPowerUp = DigitalSun_Starblitz_CharacterControllerSylas + [0x1D0]
DigitalSun_Starblitz_CharacterControllerSylas__isPlayerInQTE = DigitalSun_Starblitz_CharacterControllerSylas + [0x1D1]
DigitalSun_Starblitz_CharacterControllerSylas_passiveRunesParent = DigitalSun_Starblitz_CharacterControllerSylas + [0x1D8]
DigitalSun_Starblitz_CharacterControllerSylas__rawMoveDirection = DigitalSun_Starblitz_CharacterControllerSylas + [0x1E0]
DigitalSun_Starblitz_CharacterControllerSylas__rawAimDirection = DigitalSun_Starblitz_CharacterControllerSylas + [0x1E8]
DigitalSun_Starblitz_CharacterControllerSylas__rawInputDirection = DigitalSun_Starblitz_CharacterControllerSylas + [0x1F0]
DigitalSun_Starblitz_CharacterControllerSylas__isHoldingAttackButton = DigitalSun_Starblitz_CharacterControllerSylas + [0x1F8]
DigitalSun_Starblitz_CharacterControllerSylas__doSpartanKickOnButtonReleased = DigitalSun_Starblitz_CharacterControllerSylas + [0x1F9]
DigitalSun_Starblitz_CharacterControllerSylas__doWhirlOnButtonReleased = DigitalSun_Starblitz_CharacterControllerSylas + [0x1FA]
DigitalSun_Starblitz_CharacterControllerSylas__whirlDelayedCall = DigitalSun_Starblitz_CharacterControllerSylas + [0x200]
DigitalSun_Starblitz_CharacterControllerSylas__spartanKickDelayedCall = DigitalSun_Starblitz_CharacterControllerSylas + [0x208]
DigitalSun_Starblitz_CharacterControllerSylas__currentAttack = DigitalSun_Starblitz_CharacterControllerSylas + [0x210]
DigitalSun_Starblitz_CharacterControllerSylas__isInvisible = DigitalSun_Starblitz_CharacterControllerSylas + [0x214]
DigitalSun_Starblitz_CharacterControllerSylas__canHoldButton = DigitalSun_Starblitz_CharacterControllerSylas + [0x215]
DigitalSun_Starblitz_CharacterControllerSylas__animatorController = DigitalSun_Starblitz_CharacterControllerSylas + [0x218]
DigitalSun_Starblitz_CharacterControllerSylas__chargeSound = DigitalSun_Starblitz_CharacterControllerSylas + [0x220]
DigitalSun_Starblitz_CharacterControllerSylas__chargeSoundNextAttackParameter = DigitalSun_Starblitz_CharacterControllerSylas + [0x228]
DigitalSun_Starblitz_CharacterControllerSylas__tutorialMode = DigitalSun_Starblitz_CharacterControllerSylas + [0x260]
DigitalSun_Starblitz_CharacterControllerSylas__tutorialCanMove = DigitalSun_Starblitz_CharacterControllerSylas + [0x261]
DigitalSun_Starblitz_CharacterControllerSylas__tutorialCanLightAttack = DigitalSun_Starblitz_CharacterControllerSylas + [0x262]
DigitalSun_Starblitz_CharacterControllerSylas__tutorialCanHeavyAttack = DigitalSun_Starblitz_CharacterControllerSylas + [0x263]
DigitalSun_Starblitz_CharacterControllerSylas__tutorialCanDash = DigitalSun_Starblitz_CharacterControllerSylas + [0x264]
DigitalSun_Starblitz_CharacterControllerSylas__tutorialCanCopyAbility = DigitalSun_Starblitz_CharacterControllerSylas + [0x265]
DigitalSun_Starblitz_CharacterControllerSylas__tutorialCanUseAbility = DigitalSun_Starblitz_CharacterControllerSylas + [0x266]
DigitalSun_Starblitz_CharacterControllerSylas__tutorialCanThrow = DigitalSun_Starblitz_CharacterControllerSylas + [0x267]
DigitalSun_Starblitz_CharacterControllerSylas__tutorialCanUsePotion = DigitalSun_Starblitz_CharacterControllerSylas + [0x268]
DigitalSun_Starblitz_CharacterControllerSylas__currentPlayerInteraction = DigitalSun_Starblitz_CharacterControllerSylas + [0x270]
DigitalSun_Starblitz_CharacterControllerSylas__mouseInputAiming = DigitalSun_Starblitz_CharacterControllerSylas + [0x278]
DigitalSun_Starblitz_CharacterControllerSylas__furyLeft = DigitalSun_Starblitz_CharacterControllerSylas + [0x279]
DigitalSun_Starblitz_CharacterControllerSylas__furyRight = DigitalSun_Starblitz_CharacterControllerSylas + [0x27A]
DigitalSun_Starblitz_CharacterControllerSylas_characterAnimatorController = DigitalSun_Starblitz_CharacterControllerSylas + [0x280]
DigitalSun_Starblitz_CharacterControllerSylas__aimGizmo = DigitalSun_Starblitz_CharacterControllerSylas + [0x288]
DigitalSun_Starblitz_CharacterControllerSylas__audioListener = DigitalSun_Starblitz_CharacterControllerSylas + [0x290]
DigitalSun_Starblitz_CharacterControllerSylas__artContainer = DigitalSun_Starblitz_CharacterControllerSylas + [0x298]
DigitalSun_Starblitz_CharacterControllerSylas__rightHandPoint = DigitalSun_Starblitz_CharacterControllerSylas + [0x2A0]
DigitalSun_Starblitz_CharacterControllerSylas__leftHandPoint = DigitalSun_Starblitz_CharacterControllerSylas + [0x2A8]
DigitalSun_Starblitz_CharacterControllerSylas__currentHandPoint = DigitalSun_Starblitz_CharacterControllerSylas + [0x2B0]
DigitalSun_Starblitz_CharacterControllerSylas__overTimeAbilitiesDamaging = DigitalSun_Starblitz_CharacterControllerSylas + [0x2B8]

DigitalSun_Starblitz_ScriptableSylasInventory = DigitalSun_Starblitz_CharacterControllerSylas__inventoryInstance
DigitalSun_Starblitz_ScriptableSylasInventory_OnRuneAddedHandler = DigitalSun_Starblitz_ScriptableSylasInventory + [0x8]
DigitalSun_Starblitz_ScriptableSylasInventory_serializationData = DigitalSun_Starblitz_ScriptableSylasInventory + [0x18]
DigitalSun_Starblitz_ScriptableSylasInventory__runeAbilities = DigitalSun_Starblitz_ScriptableSylasInventory + [0x58]
DigitalSun_Starblitz_ScriptableSylasInventory__potion = DigitalSun_Starblitz_ScriptableSylasInventory + [0x60]
DigitalSun_Starblitz_ScriptableSylasInventory__specialObjectsAmount = DigitalSun_Starblitz_ScriptableSylasInventory + [0x68]
DigitalSun_Starblitz_ScriptableSylasInventory__superSpecialObjectsAmount = DigitalSun_Starblitz_ScriptableSylasInventory + [0x6C]

DigitalSun_Starblitz_PotionController = DigitalSun_Starblitz_ScriptableSylasInventory__potion
DigitalSun_Starblitz_PotionController_OnPotionUsedHandler = DigitalSun_Starblitz_PotionController + [0x8]
DigitalSun_Starblitz_PotionController_OnPotionsRefillHandler = DigitalSun_Starblitz_PotionController + [0x10]
DigitalSun_Starblitz_PotionController__hp = DigitalSun_Starblitz_PotionController + [0x10]
DigitalSun_Starblitz_PotionController__mana = DigitalSun_Starblitz_PotionController + [0x14]
DigitalSun_Starblitz_PotionController__numberOfUsesRemaining = DigitalSun_Starblitz_PotionController + [0x18]
DigitalSun_Starblitz_PotionController__statsModifiersAdditions = DigitalSun_Starblitz_PotionController + [0x20]
DigitalSun_Starblitz_PotionController__initialized = DigitalSun_Starblitz_PotionController + [0x28]

# 31D76DC player is Invincible
AddCheat('Invincible to player', '玩家無敵')
Hack('A8 7A 44 39 A8 00 00 34','MOV W8,#1')
Hack('A8 7A 44 39 88 02 00 35 13 04 00 B4','MOV W8,#1')
Hack('88 7A 44 39 E8 00 00 34','MOV W8,#1')
Hack('88 7A 44 39 A8 00 00 34','MOV W8,#1')

# 31EDECC movement speed
AddCheat('Movement speed 2x', '移動速度 2x')
Hack('08 1C A0 4E 88 ? ? 39 C8 00 00 37 ? ? ? ? ? ? ? 91 ? ? ? ? 28 00 80 52 88 ? ? 39 68 26 40 F9', 'FADD S8, S0, S0')

# 31E6FA4 dash cooldown
AddCheat('Dash No Cooldown', '飛奔無冷卻時間(無延遲)')
Hack('61 8A 40 BD BF FF 39 A9','FMOV S1, WZR')

# 2E7B8A8 attack power
# 31358B8 magic attack power
AddCheat('Attack Power 5x', '攻擊力量 5x')
CodeCave('08 01 26 1E E1 03 16 2A',['FMOV W8, S8','ADD W8, W8, W8, LSL 2','RET'])

# 30DDF34 add Currency
AddCheat('Currency Received 5x', '金幣獲取 5x')
Hack('F4 03 01 2A A8 ? ? 39 F3 03 00 AA C8 00 00 37 ? ? ? ? ? ? ? 91 ? ? ? ? 28 00 80 52 A8 ? ? 39 ? ? ? ? 75 12 40 B9 C8 ? ? 39 C8 00 00 37 ? ? ? ? ? ? ? 91 ? ? ? ? 28 00 80 52 C8 ? ? 39 ? ? ? ? 00 ? ? F9 ? ? ? ? 00 03 00 B4 09 38 46 B9 A8 02 14 0B','ADD W20, W1, W1, LSL 2')

# 30DE004 inf Currency
AddCheat('Currency do not decrease', '金幣不減')
Hack('F4 03 01 2A A8 ? ? 39 F3 03 00 AA C8 00 00 37 ? ? ? ? ? ? ? 91 ? ? ? ? 28 00 80 52 A8 ? ? 39 ? ? ? ? 75 12 40 B9 C8 ? ? 39 C8 00 00 37 ? ? ? ? ? ? ? 91 ? ? ? ? 28 00 80 52 C8 ? ? 39 ? ? ? ? 00 ? ? F9 ? ? ? ? 00 03 00 B4 09 38 46 B9 A8 02 14 4B','MOV W20, WZR')

# 2ADF828 protion used
AddCheat('Protion do not decrease', '藥水不減')
Hack('08 05 00 51 68 1A 00 B9 ? ? ? ? 08 ? ? F9','NOP')

# 31D97E8 inf Mana
AddCheat('Mana do not decrease', '魔力不減')
Hack('F4 03 01 2A A8 ? ? 39 F3 03 00 AA C8 00 00 37 ? ? ? ? ? ? ? 91 ? ? ? ? 28 00 80 52 A8 ? ? 39 80 02 22 1E','MOV W20, WZR')


################################# END #######################################

HackComplete()
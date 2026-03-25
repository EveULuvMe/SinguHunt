/// SinguHunt v2 - Dragon Ball Singularity Hunting Game for EVE Frontier
///
/// Game Flow:
/// 1. Every day at 00:00 UTC, a new hunt starts from the bulletin board (start gate)
/// 2. A configurable number of Singu are scattered across the selected active gate locations
/// 3. Each dragon ball can only be claimed by the FIRST player to arrive
/// 4. Collect the required number of Singu and deposit them at the end gate
/// 5. Earn a permanent, non-transferable achievement NFT
module singuhunt::singuhunt {
    use sui::balance::{Self, Balance};
    use sui::clock::{Self, Clock};
    use sui::coin::{Self, Coin};
    use sui::dynamic_field;
    use sui::event;
    use sui::hash;
    use sui::table::{Self, Table};
    use sui::bcs;
    use singuvault::lux::LUX;
    use singuhunt::sig_verify;

    // ============ Error Codes ============
    const E_HUNT_NOT_ACTIVE: u64 = 1;
    const E_ALREADY_COLLECTED: u64 = 2;
    const E_INVALID_BALL: u64 = 3;
    const E_HUNT_EXPIRED: u64 = 4;
    const E_INCOMPLETE_COLLECTION: u64 = 5;
    const E_ALREADY_HAS_ACHIEVEMENT: u64 = 6;
    const E_NOT_TOKEN_OWNER: u64 = 7;
    const E_BALL_ALREADY_TAKEN: u64 = 8;
    const E_NOT_ADMIN: u64 = 9;
    const E_INVALID_GATE_INDEX: u64 = 10;
    const E_TICKET_EXPIRED: u64 = 11;
    const E_INVALID_TICKET: u64 = 12;
    const E_TICKET_REPLAY: u64 = 13;
    const E_ASSEMBLY_MISMATCH: u64 = 14;
    const E_TICKET_SIGNER_NOT_SET: u64 = 15;
    const E_INVALID_ACTIVE_GATE_COUNT: u64 = 16;
    const E_POOL_GATE_NOT_CONFIGURED: u64 = 17;
    const E_DUPLICATE_ACTIVE_GATE: u64 = 18;
    const E_INVALID_REQUIRED_SINGU_COUNT: u64 = 19;
    const E_ALREADY_DELIVERED: u64 = 20;
    const E_DELIVER_TICKET_REPLAY: u64 = 21;
    const E_INVALID_DELIVER_GATE: u64 = 22;
    const E_BALL_NOT_DELIVERED: u64 = 23;
    const E_INVALID_MODE: u64 = 24;
    const E_EPOCH_ALREADY_WON: u64 = 25;
    const E_REGISTRATION_NOT_OPEN: u64 = 26;
    const E_ALREADY_REGISTERED: u64 = 27;
    const E_NOT_REGISTERED: u64 = 28;
    const E_ALL_WINNER_SLOTS_FILLED: u64 = 29;
    const E_REGISTRATION_STILL_OPEN: u64 = 30;
    const E_HUNT_ALREADY_ACTIVE: u64 = 31;
    const E_TEAM_REGISTRATION_NOT_FINALIZED: u64 = 32;
    const E_TEAM_ASSIGNMENT_MISSING: u64 = 33;
    const E_TEAM_REGISTRATION_CANCELLED: u64 = 34;
    const E_TEAM_GATE_ALREADY_CLAIMED: u64 = 35;
    const E_TEAM_INCOMPLETE: u64 = 36;
    const E_TEAM_ALREADY_FINISHED: u64 = 37;
    const E_NOT_TEAM_MODE: u64 = 38;
    const E_INVALID_REVEAL_TIME: u64 = 39;
    const E_INVALID_REGISTRATION_FEE: u64 = 40;

    // ============ Constants ============
    const DRAGON_BALL_COUNT: u64 = 7;
    const HUNT_DURATION_MS: u64 = 86_400_000; // 24 hours
    const WINNER_PCT_NUMERATOR: u64 = 5;   // top 5%
    const WINNER_PCT_DENOMINATOR: u64 = 100;
    const TEAM_SIZE: u64 = 3;
    const ACHIEVEMENT_IMAGE_URL: vector<u8> = b"https://dapp-seven-henna.vercel.app/NFT.png";

    // ============ Hunt Modes ============
    const MODE_SOLO_RACE: u8 = 1;
    const MODE_TEAM_RACE: u8 = 2;
    const MODE_DEEP_DECRYPT: u8 = 3;
    const MODE_LARGE_ARENA: u8 = 4;
    const MODE_OBSTACLE_RUN: u8 = 5;

    // Registration fee schedule in LUX smallest units (9 decimals)
    const REG_FEE_SOLO_RACE: u64 = 12_000_000_000;     // 12 LUX
    const REG_FEE_TEAM_RACE: u64 = 15_000_000_000;     // 15 LUX
    const REG_FEE_DEEP_DECRYPT: u64 = 30_000_000_000;  // 30 LUX
    const REG_FEE_LARGE_ARENA: u64 = 22_000_000_000;   // 22 LUX
    const REG_FEE_OBSTACLE_RUN: u64 = 18_000_000_000;  // 18 LUX

    // ============ Dynamic Field Keys ============

    /// Stores hunt mode (u8) on GameState
    public struct HuntModeKey has copy, drop, store {}

    /// Stores the winner address for a given epoch. Key per epoch.
    public struct EpochWinnerKey has copy, drop, store { epoch: u64 }

    /// Registration phase: is registration currently open?
    public struct RegPhaseKey has copy, drop, store {}

    /// Registration end timestamp (ms)
    public struct RegEndTimeKey has copy, drop, store {}

    /// Registration mode (u8) — which mode players are registering for
    public struct RegModeKey has copy, drop, store {}

    /// Planned game start timestamp for the next session
    public struct RegGameStartTimeKey has copy, drop, store {}

    /// Per-player registration check. Existence = registered.
    public struct RegPlayerKey has copy, drop, store { epoch: u64, player: address }

    /// Number of registered players for an epoch
    public struct RegCountKey has copy, drop, store { epoch: u64 }

    /// Player registration order (1-based).
    public struct RegOrderKey has copy, drop, store { epoch: u64, order: u64 }

    /// Registration order lookup for a player.
    public struct RegPositionKey has copy, drop, store { epoch: u64, player: address }

    /// Number of successful registrations after trimming incomplete teams.
    public struct SuccessfulRegCountKey has copy, drop, store { epoch: u64 }

    /// Number of teams for an epoch.
    public struct TeamCountKey has copy, drop, store { epoch: u64 }

    /// Whether team registration has been finalized for an epoch.
    public struct TeamRegistrationFinalizedKey has copy, drop, store { epoch: u64 }

    /// Team assignment for a player in an epoch.
    public struct TeamAssignmentKey has copy, drop, store { epoch: u64, player: address }

    /// Generic per-epoch achievement claim marker for any mode.
    public struct EpochAchievementClaimKey has copy, drop, store { epoch: u64, player: address }

    /// Team roster lookup.
    public struct TeamRosterKey has copy, drop, store { epoch: u64, team_id: u64 }

    /// Per-team per-gate completion marker.
    public struct TeamGateClaimKey has copy, drop, store { epoch: u64, team_id: u64, ball_index: u64 }

    /// Maximum number of winners for an epoch (calculated from registration count)
    public struct WinnerSlotsKey has copy, drop, store { epoch: u64 }

    /// Current winner count for an epoch (incremented on each successful claim)
    public struct WinnerCountKey has copy, drop, store { epoch: u64 }

    // ============ Objects ============

    /// Admin capability
    public struct AdminCap has key, store {
        id: UID,
    }

    /// Gate location info for the game
    public struct GateLocation has store, copy, drop {
        /// On-chain Gate object ID (0x... address)
        gate_id: address,
        /// Display name
        name: vector<u8>,
        /// Whether a dragon ball is placed here
        has_ball: bool,
        /// Whether the ball has been collected
        ball_collected: bool,
        /// Who collected the ball (0x0 if uncollected)
        collector: address,
        /// Whether the ball has been delivered back to the home gate
        ball_delivered: bool,
        /// Who delivered the ball back to the home gate
        deliverer: address,
    }

    /// Candidate gate that can be activated for a daily hunt
    public struct GateConfig has store, copy, drop {
        gate_id: address,
        name: vector<u8>,
    }

    /// Team race assignment state for a player.
    public struct TeamAssignment has store, copy, drop {
        registration_index: u64,
        team_id: u64,
        slot: u64,
        active: bool,
        reveal_at: u64,
    }

    /// Team race roster and progress.
    public struct TeamRoster has store, copy, drop {
        team_id: u64,
        member_1: address,
        member_2: address,
        member_3: address,
        completed_count: u64,
        finished: bool,
        winner_rank: u64,
        finished_at: u64,
        reveal_at: u64,
    }

    /// Main game state - shared object
    public struct GameState has key {
        id: UID,
        /// Current hunt epoch
        current_epoch: u64,
        /// Hunt timing
        hunt_start_time: u64,
        hunt_end_time: u64,
        hunt_active: bool,
        /// Start gate (bulletin board)
        start_gate: address,
        start_gate_name: vector<u8>,
        /// End gate (deposit point)
        end_gate: address,
        end_gate_name: vector<u8>,
        /// Number of active Singu gates required for the current ruleset.
        required_singu_count: u64,
        /// Candidate gate pool. Admin can register 20+ gates here.
        gate_pool: vector<GateConfig>,
        /// Active dragon ball locations (gates) for the current epoch
        ball_gates: vector<GateLocation>,
        /// Track per-epoch collections: key = epoch, value = table of player -> collected count
        epoch_collections: Table<u64, Table<address, u64>>,
        /// Achievement holders
        achievement_holders: Table<address, u64>,
        /// Trusted off-chain signer that attests the player is interacting from a valid assembly context
        ticket_signer: address,
        /// Track used claim tickets by digest to block replay attacks
        used_claim_tickets: Table<address, bool>,
        /// Accumulated registration fees collected in LUX
        registration_fee_pool: Balance<LUX>,
        /// Stats
        total_achievements: u64,
        total_hunts: u64,
        total_lux_collected: u64,
    }

    /// Dragon Ball token - collected at gate locations
    public struct DragonBall has key, store {
        id: UID,
        epoch: u64,
        /// Which active ball index this token represents for the epoch
        star_index: u64,
        /// Gate where it was collected
        gate_id: address,
        gate_name: vector<u8>,
        /// When it expires
        expires_at: u64,
        /// Who collected it
        collector: address,
        /// Whether it has been delivered to the home gate
        delivered: bool,
        /// When it was delivered to the home gate
        delivered_at: u64,
    }

    /// Permanent achievement NFT - soulbound (no `store`)
    public struct AchievementNFT has key {
        id: UID,
        completed_epoch: u64,
        earned_at: u64,
        owner: address,
        achievement_number: u64,
        name: vector<u8>,
        description: vector<u8>,
        image_url: vector<u8>,
    }

    // ============ Events ============

    public struct HuntStarted has copy, drop {
        epoch: u64,
        mode: u8,
        start_time: u64,
        end_time: u64,
        start_gate: address,
        end_gate: address,
        ball_gates: vector<address>,
    }

    public struct DragonBallCollected has copy, drop {
        epoch: u64,
        star_index: u64,
        collector: address,
        gate_id: address,
    }

    public struct AchievementEarned has copy, drop {
        epoch: u64,
        player: address,
        achievement_number: u64,
    }

    public struct DragonBallDelivered has copy, drop {
        epoch: u64,
        star_index: u64,
        deliverer: address,
        gate_id: address,
    }

    public struct HuntCompleted has copy, drop {
        epoch: u64,
    }

    public struct HuntExpired has copy, drop {
        epoch: u64,
    }

    public struct DragonBallBurned has copy, drop {
        epoch: u64,
        star_index: u64,
        burner: address,
    }

    public struct GateConfigured has copy, drop {
        role: vector<u8>,
        index: u64,
        gate_id: address,
        name: vector<u8>,
    }

    public struct TicketSignerConfigured has copy, drop {
        signer: address,
    }

    public struct RequiredSinguCountConfigured has copy, drop {
        count: u64,
    }

    public struct RegistrationOpened has copy, drop {
        next_epoch: u64,
        mode: u8,
        reg_end_time: u64,
        registration_fee_lux: u64,
    }

    public struct PlayerRegistered has copy, drop {
        next_epoch: u64,
        player: address,
        reg_count: u64,
        fee_paid_lux: u64,
    }

    public struct RegistrationFeesWithdrawn has copy, drop {
        amount: u64,
    }

    public struct TeamRegistrationFinalized has copy, drop {
        epoch: u64,
        total_registered: u64,
        successful_registered: u64,
        team_count: u64,
        reveal_at: u64,
    }

    public struct TeamAssigned has copy, drop {
        epoch: u64,
        team_id: u64,
        member_1: address,
        member_2: address,
        member_3: address,
        reveal_at: u64,
    }

    public struct TeamGateCompleted has copy, drop {
        epoch: u64,
        team_id: u64,
        star_index: u64,
        player: address,
    }

    public struct TeamFinished has copy, drop {
        epoch: u64,
        team_id: u64,
        finisher: address,
        winner_rank: u64,
    }

    public struct DeepDecryptSolved has copy, drop {
        epoch: u64,
        player: address,
        winner_rank: u64,
    }

    // ============ Init ============

    fun init(ctx: &mut TxContext) {
        let admin_cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(admin_cap, ctx.sender());

        let game_state = GameState {
            id: object::new(ctx),
            current_epoch: 0,
            hunt_start_time: 0,
            hunt_end_time: 0,
            hunt_active: false,
            start_gate: @0x0,
            start_gate_name: b"",
            end_gate: @0x0,
            end_gate_name: b"",
            required_singu_count: DRAGON_BALL_COUNT,
            gate_pool: vector::empty(),
            ball_gates: vector::empty(),
            epoch_collections: table::new(ctx),
            achievement_holders: table::new(ctx),
            ticket_signer: @0x0,
            used_claim_tickets: table::new(ctx),
            registration_fee_pool: balance::zero(),
            total_achievements: 0,
            total_hunts: 0,
            total_lux_collected: 0,
        };
        transfer::share_object(game_state);
    }

    // ============ Admin: Configure Gates ============

    /// Set the start gate (bulletin board)
    public entry fun set_start_gate(
        _admin: &AdminCap,
        game: &mut GameState,
        gate_id: address,
        name: vector<u8>,
    ) {
        game.start_gate = gate_id;
        game.start_gate_name = name;
        event::emit(GateConfigured { role: b"start", index: 0, gate_id, name });
    }

    /// Set the end gate (deposit point)
    public entry fun set_end_gate(
        _admin: &AdminCap,
        game: &mut GameState,
        gate_id: address,
        name: vector<u8>,
    ) {
        game.end_gate = gate_id;
        game.end_gate_name = name;
        event::emit(GateConfigured { role: b"end", index: 0, gate_id, name });
    }

    /// Add or update a candidate gate location in the daily hunt pool.
    public entry fun set_pool_gate(
        _admin: &AdminCap,
        game: &mut GameState,
        index: u64,
        gate_id: address,
        name: vector<u8>,
    ) {
        let gate = GateConfig {
            gate_id,
            name,
        };

        // Extend or replace
        while (game.gate_pool.length() <= index) {
            game.gate_pool.push_back(GateConfig {
                gate_id: @0x0,
                name: b"",
            });
        };
        *&mut game.gate_pool[index] = gate;

        event::emit(GateConfigured { role: b"pool", index, gate_id, name });
    }

    /// Backwards-compatible helper: configure the first 7 legacy entries in the gate pool.
    public entry fun set_ball_gate(
        _admin: &AdminCap,
        game: &mut GameState,
        index: u64,
        gate_id: address,
        name: vector<u8>,
    ) {
        assert!(index < DRAGON_BALL_COUNT, E_INVALID_GATE_INDEX);
        set_pool_gate(_admin, game, index, gate_id, name);

        event::emit(GateConfigured { role: b"ball", index, gate_id, name });
    }

    /// Configure the trusted ticket signer used to authorize in-game claims.
    public entry fun set_ticket_signer(
        _admin: &AdminCap,
        game: &mut GameState,
        signer: address,
    ) {
        game.ticket_signer = signer;
        event::emit(TicketSignerConfigured { signer });
    }

    /// Configure how many Singu must be activated daily and how many are required to finish the hunt.
    public entry fun set_required_singu_count(
        _admin: &AdminCap,
        game: &mut GameState,
        count: u64,
    ) {
        assert!(count > 0, E_INVALID_REQUIRED_SINGU_COUNT);
        game.required_singu_count = count;
        event::emit(RequiredSinguCountConfigured { count });
    }

    fun load_reg_count(game: &GameState, epoch: u64): u64 {
        if (dynamic_field::exists_(&game.id, RegCountKey { epoch })) {
            *dynamic_field::borrow<RegCountKey, u64>(&game.id, RegCountKey { epoch })
        } else {
            0
        }
    }

    fun load_team_count(game: &GameState, epoch: u64): u64 {
        if (dynamic_field::exists_(&game.id, TeamCountKey { epoch })) {
            *dynamic_field::borrow<TeamCountKey, u64>(&game.id, TeamCountKey { epoch })
        } else {
            0
        }
    }

    fun calc_winner_slots(total: u64): u64 {
        if (total == 0) {
            0
        } else {
            let numerator = total * WINNER_PCT_NUMERATOR + WINNER_PCT_DENOMINATOR - 1;
            let slots = numerator / WINNER_PCT_DENOMINATOR;
            if (slots == 0) { 1 } else { slots }
        }
    }

    fun random_index(seed: u64, epoch: u64, round: u64, max: u64): u64 {
        let mut bytes = bcs::to_bytes(&seed);
        vector::append(&mut bytes, bcs::to_bytes(&epoch));
        vector::append(&mut bytes, bcs::to_bytes(&round));
        let hash_bytes = hash::blake2b256(&bytes);

        let mut value = 0u64;
        let mut i = 0u64;
        while (i < 8) {
            value = value * 256 + (hash_bytes[i] as u64);
            i = i + 1;
        };

        if (max == 0) 0 else value % max
    }

    fun shuffle_addresses(values: &mut vector<address>, seed: u64, epoch: u64) {
        let mut i = values.length();
        while (i > 1) {
            i = i - 1;
            let j = random_index(seed, epoch, i, i + 1);
            vector::swap(values, i, j);
        };
    }

    // ============ Registration ============

    /// Admin opens registration for the next hunt session.
    /// `reg_end_time_ms` is the UTC timestamp (ms) when registration closes.
    /// The next epoch is current_epoch + 1 (will be incremented when hunt starts).
    public entry fun open_registration(
        _admin: &AdminCap,
        game: &mut GameState,
        mode: u8,
        reg_end_time_ms: u64,
        game_start_time_ms: u64,
        clock: &Clock,
    ) {
        assert!(mode >= MODE_SOLO_RACE && mode <= MODE_OBSTACLE_RUN, E_INVALID_MODE);
        let now = clock::timestamp_ms(clock);
        assert!(reg_end_time_ms > now, E_HUNT_EXPIRED);
        assert!(game_start_time_ms > reg_end_time_ms, E_INVALID_REVEAL_TIME);

        let next_epoch = game.current_epoch + 1;

        // Set registration phase flags
        if (dynamic_field::exists_(&game.id, RegPhaseKey {})) {
            *dynamic_field::borrow_mut(&mut game.id, RegPhaseKey {}) = true;
        } else {
            dynamic_field::add(&mut game.id, RegPhaseKey {}, true);
        };

        if (dynamic_field::exists_(&game.id, RegEndTimeKey {})) {
            *dynamic_field::borrow_mut(&mut game.id, RegEndTimeKey {}) = reg_end_time_ms;
        } else {
            dynamic_field::add(&mut game.id, RegEndTimeKey {}, reg_end_time_ms);
        };

        if (dynamic_field::exists_(&game.id, RegModeKey {})) {
            *dynamic_field::borrow_mut(&mut game.id, RegModeKey {}) = mode;
        } else {
            dynamic_field::add(&mut game.id, RegModeKey {}, mode);
        };

        if (dynamic_field::exists_(&game.id, RegGameStartTimeKey {})) {
            *dynamic_field::borrow_mut(&mut game.id, RegGameStartTimeKey {}) = game_start_time_ms;
        } else {
            dynamic_field::add(&mut game.id, RegGameStartTimeKey {}, game_start_time_ms);
        };

        // Initialize reg count for next epoch
        if (!dynamic_field::exists_(&game.id, RegCountKey { epoch: next_epoch })) {
            dynamic_field::add(&mut game.id, RegCountKey { epoch: next_epoch }, 0u64);
        };

        if (!dynamic_field::exists_(&game.id, SuccessfulRegCountKey { epoch: next_epoch })) {
            dynamic_field::add(&mut game.id, SuccessfulRegCountKey { epoch: next_epoch }, 0u64);
        } else {
            *dynamic_field::borrow_mut(&mut game.id, SuccessfulRegCountKey { epoch: next_epoch }) = 0u64;
        };

        if (!dynamic_field::exists_(&game.id, TeamCountKey { epoch: next_epoch })) {
            dynamic_field::add(&mut game.id, TeamCountKey { epoch: next_epoch }, 0u64);
        } else {
            *dynamic_field::borrow_mut(&mut game.id, TeamCountKey { epoch: next_epoch }) = 0u64;
        };

        if (!dynamic_field::exists_(&game.id, TeamRegistrationFinalizedKey { epoch: next_epoch })) {
            dynamic_field::add(&mut game.id, TeamRegistrationFinalizedKey { epoch: next_epoch }, false);
        } else {
            *dynamic_field::borrow_mut(&mut game.id, TeamRegistrationFinalizedKey { epoch: next_epoch }) = false;
        };

        event::emit(RegistrationOpened {
            next_epoch,
            mode,
            reg_end_time: reg_end_time_ms,
            registration_fee_lux: registration_fee_for_mode(mode),
        });
    }

    /// Player registers for the upcoming hunt session.
    public entry fun register_for_hunt(
        game: &mut GameState,
        fee_coin: Coin<LUX>,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        let now = clock::timestamp_ms(clock);
        let player = ctx.sender();
        let next_epoch = game.current_epoch + 1;
        let mode = *dynamic_field::borrow<RegModeKey, u8>(&game.id, RegModeKey {});
        let required_fee = registration_fee_for_mode(mode);
        let paid_fee = coin::value(&fee_coin);

        // Check registration is open
        assert!(
            dynamic_field::exists_(&game.id, RegPhaseKey {}) &&
            *dynamic_field::borrow<RegPhaseKey, bool>(&game.id, RegPhaseKey {}),
            E_REGISTRATION_NOT_OPEN,
        );

        // Check registration window not expired
        let reg_end = *dynamic_field::borrow<RegEndTimeKey, u64>(&game.id, RegEndTimeKey {});
        assert!(now <= reg_end, E_REGISTRATION_NOT_OPEN);

        // Check not already registered
        assert!(
            !dynamic_field::exists_(&game.id, RegPlayerKey { epoch: next_epoch, player }),
            E_ALREADY_REGISTERED,
        );
        assert!(paid_fee == required_fee, E_INVALID_REGISTRATION_FEE);

        // Register player
        dynamic_field::add(&mut game.id, RegPlayerKey { epoch: next_epoch, player }, true);
        balance::join(&mut game.registration_fee_pool, coin::into_balance(fee_coin));
        game.total_lux_collected = game.total_lux_collected + paid_fee;

        // Increment count
        let count = dynamic_field::borrow_mut<RegCountKey, u64>(&mut game.id, RegCountKey { epoch: next_epoch });
        *count = *count + 1;
        let registration_index = *count;

        dynamic_field::add(&mut game.id, RegPositionKey { epoch: next_epoch, player }, registration_index);
        dynamic_field::add(&mut game.id, RegOrderKey { epoch: next_epoch, order: registration_index }, player);

        event::emit(PlayerRegistered {
            next_epoch,
            player,
            reg_count: registration_index,
            fee_paid_lux: paid_fee,
        });
    }

    public entry fun withdraw_registration_fees(
        _admin: &AdminCap,
        game: &mut GameState,
        amount: u64,
        ctx: &mut TxContext,
    ) {
        let withdrawn = balance::split(&mut game.registration_fee_pool, amount);
        event::emit(RegistrationFeesWithdrawn { amount });
        transfer::public_transfer(coin::from_balance(withdrawn, ctx), ctx.sender());
    }

    public entry fun finalize_team_registration(
        _admin: &AdminCap,
        game: &mut GameState,
        random_seed: u64,
        clock: &Clock,
    ) {
        let epoch = game.current_epoch + 1;
        let now = clock::timestamp_ms(clock);

        assert!(
            dynamic_field::exists_(&game.id, RegModeKey {}) &&
            *dynamic_field::borrow<RegModeKey, u8>(&game.id, RegModeKey {}) == MODE_TEAM_RACE,
            E_NOT_TEAM_MODE,
        );

        let reg_end = *dynamic_field::borrow<RegEndTimeKey, u64>(&game.id, RegEndTimeKey {});
        assert!(now > reg_end, E_REGISTRATION_STILL_OPEN);

        let already_finalized = *dynamic_field::borrow<TeamRegistrationFinalizedKey, bool>(
            &game.id,
            TeamRegistrationFinalizedKey { epoch },
        );
        assert!(!already_finalized, E_TEAM_REGISTRATION_NOT_FINALIZED);

        let total_registered = load_reg_count(game, epoch);
        let successful_registered = total_registered - (total_registered % TEAM_SIZE);
        let team_count = successful_registered / TEAM_SIZE;
        let game_start_time = *dynamic_field::borrow<RegGameStartTimeKey, u64>(&game.id, RegGameStartTimeKey {});
        let reveal_at = game_start_time;

        let success_ref = dynamic_field::borrow_mut<SuccessfulRegCountKey, u64>(
            &mut game.id,
            SuccessfulRegCountKey { epoch },
        );
        *success_ref = successful_registered;

        let team_count_ref = dynamic_field::borrow_mut<TeamCountKey, u64>(&mut game.id, TeamCountKey { epoch });
        *team_count_ref = team_count;

        let mut successful_players = vector::empty<address>();
        let mut index = 1u64;
        while (index <= total_registered) {
            let player = *dynamic_field::borrow<RegOrderKey, address>(&game.id, RegOrderKey { epoch, order: index });
            if (index <= successful_registered) {
                successful_players.push_back(player);
            } else {
                dynamic_field::add(
                    &mut game.id,
                    TeamAssignmentKey { epoch, player },
                    TeamAssignment {
                        registration_index: index,
                        team_id: 0,
                        slot: 0,
                        active: false,
                        reveal_at,
                    },
                );
            };
            index = index + 1;
        };

        shuffle_addresses(&mut successful_players, random_seed, epoch);

        let mut cursor = 0u64;
        let mut team_id = 1u64;
        while (team_id <= team_count) {
            let member_1 = successful_players[cursor];
            let member_2 = successful_players[cursor + 1];
            let member_3 = successful_players[cursor + 2];
            let member_1_index = *dynamic_field::borrow<RegPositionKey, u64>(
                &game.id,
                RegPositionKey { epoch, player: member_1 },
            );
            let member_2_index = *dynamic_field::borrow<RegPositionKey, u64>(
                &game.id,
                RegPositionKey { epoch, player: member_2 },
            );
            let member_3_index = *dynamic_field::borrow<RegPositionKey, u64>(
                &game.id,
                RegPositionKey { epoch, player: member_3 },
            );

            dynamic_field::add(
                &mut game.id,
                TeamRosterKey { epoch, team_id },
                TeamRoster {
                    team_id,
                    member_1,
                    member_2,
                    member_3,
                    completed_count: 0,
                    finished: false,
                    winner_rank: 0,
                    finished_at: 0,
                    reveal_at,
                },
            );

            dynamic_field::add(
                &mut game.id,
                TeamAssignmentKey { epoch, player: member_1 },
                TeamAssignment {
                    registration_index: member_1_index,
                    team_id,
                    slot: 1,
                    active: true,
                    reveal_at,
                },
            );
            dynamic_field::add(
                &mut game.id,
                TeamAssignmentKey { epoch, player: member_2 },
                TeamAssignment {
                    registration_index: member_2_index,
                    team_id,
                    slot: 2,
                    active: true,
                    reveal_at,
                },
            );
            dynamic_field::add(
                &mut game.id,
                TeamAssignmentKey { epoch, player: member_3 },
                TeamAssignment {
                    registration_index: member_3_index,
                    team_id,
                    slot: 3,
                    active: true,
                    reveal_at,
                },
            );

            event::emit(TeamAssigned {
                epoch,
                team_id,
                member_1,
                member_2,
                member_3,
                reveal_at,
            });

            cursor = cursor + TEAM_SIZE;
            team_id = team_id + 1;
        };

        *dynamic_field::borrow_mut<TeamRegistrationFinalizedKey, bool>(
            &mut game.id,
            TeamRegistrationFinalizedKey { epoch },
        ) = true;

        event::emit(TeamRegistrationFinalized {
            epoch,
            total_registered,
            successful_registered,
            team_count,
            reveal_at,
        });
    }

    // ============ Admin: Start Hunt ============

    fun start_hunt_internal(
        game: &mut GameState,
        selected_pool_indices: vector<u64>,
        mode: u8,
        game_duration_ms: u64,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        // Validate mode
        assert!(mode >= MODE_SOLO_RACE && mode <= MODE_OBSTACLE_RUN, E_INVALID_MODE);

        // Expire previous hunt if active
        if (game.hunt_active) {
            game.hunt_active = false;
            event::emit(HuntExpired { epoch: game.current_epoch });
        };

        assert!(
            selected_pool_indices.length() == game.required_singu_count,
            E_INVALID_ACTIVE_GATE_COUNT
        );

        game.current_epoch = game.current_epoch + 1;
        let epoch = game.current_epoch;
        let now = clock::timestamp_ms(clock);

        // Close registration phase
        if (dynamic_field::exists_(&game.id, RegPhaseKey {})) {
            *dynamic_field::borrow_mut(&mut game.id, RegPhaseKey {}) = false;
        };

        let winner_slots = if (mode == MODE_TEAM_RACE) {
            let finalized = if (dynamic_field::exists_(&game.id, TeamRegistrationFinalizedKey { epoch })) {
                *dynamic_field::borrow<TeamRegistrationFinalizedKey, bool>(
                    &game.id,
                    TeamRegistrationFinalizedKey { epoch },
                )
            } else {
                false
            };
            assert!(finalized, E_TEAM_REGISTRATION_NOT_FINALIZED);
            calc_winner_slots(load_team_count(game, epoch))
        } else {
            let reg_count = load_reg_count(game, epoch);
            if (reg_count == 0) {
                1
            } else {
                calc_winner_slots(reg_count)
            }
        };

        if (dynamic_field::exists_(&game.id, WinnerSlotsKey { epoch })) {
            *dynamic_field::borrow_mut(&mut game.id, WinnerSlotsKey { epoch }) = winner_slots;
        } else {
            dynamic_field::add(&mut game.id, WinnerSlotsKey { epoch }, winner_slots);
        };

        // Initialize winner count
        if (!dynamic_field::exists_(&game.id, WinnerCountKey { epoch })) {
            dynamic_field::add(&mut game.id, WinnerCountKey { epoch }, 0u64);
        };

        // Store hunt mode as dynamic field
        if (dynamic_field::exists_(&game.id, HuntModeKey {})) {
            *dynamic_field::borrow_mut(&mut game.id, HuntModeKey {}) = mode;
        } else {
            dynamic_field::add(&mut game.id, HuntModeKey {}, mode);
        };

        game.hunt_start_time = now;
        game.hunt_end_time = now + game_duration_ms;
        game.hunt_active = true;
        game.total_hunts = game.total_hunts + 1;

        // Rebuild the active gate set from the selected gate pool entries.
        game.ball_gates = vector::empty();

        let mut i: u64 = 0;
        let mut ball_gate_ids = vector::empty<address>();
        while (i < selected_pool_indices.length()) {
            let pool_index = selected_pool_indices[i];
            assert!(pool_index < game.gate_pool.length(), E_INVALID_GATE_INDEX);

            let pool_gate = &game.gate_pool[pool_index];
            assert!(pool_gate.gate_id != @0x0, E_POOL_GATE_NOT_CONFIGURED);

            let mut j: u64 = 0;
            while (j < game.ball_gates.length()) {
                let existing_gate = &game.ball_gates[j];
                assert!(existing_gate.gate_id != pool_gate.gate_id, E_DUPLICATE_ACTIVE_GATE);
                j = j + 1;
            };

            let gate = GateLocation {
                gate_id: pool_gate.gate_id,
                name: pool_gate.name,
                has_ball: true,
                ball_collected: false,
                collector: @0x0,
                ball_delivered: false,
                deliverer: @0x0,
            };

            game.ball_gates.push_back(gate);
            ball_gate_ids.push_back(pool_gate.gate_id);
            i = i + 1;
        };

        // Create epoch tracking table
        if (!game.epoch_collections.contains(epoch)) {
            game.epoch_collections.add(epoch, table::new(ctx));
        };

        event::emit(HuntStarted {
            epoch,
            mode,
            start_time: now,
            end_time: now + game_duration_ms,
            start_gate: game.start_gate,
            end_gate: game.end_gate,
            ball_gates: ball_gate_ids,
        });
    }

    /// Start a new hunt by selecting gates from the candidate pool with a specific mode and duration.
    public entry fun start_hunt_with_selection(
        _admin: &AdminCap,
        game: &mut GameState,
        selected_pool_indices: vector<u64>,
        mode: u8,
        game_duration_ms: u64,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        start_hunt_internal(game, selected_pool_indices, mode, game_duration_ms, clock, ctx);
    }

    /// Backwards-compatible helper: start a Solo Race hunt using pool entries 0..required_singu_count-1.
    public entry fun start_hunt(
        _admin: &AdminCap,
        game: &mut GameState,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        let mut selected_pool_indices = vector::empty<u64>();
        let mut i: u64 = 0;
        while (i < game.required_singu_count) {
            selected_pool_indices.push_back(i);
            i = i + 1;
        };
        start_hunt_internal(game, selected_pool_indices, MODE_SOLO_RACE, HUNT_DURATION_MS, clock, ctx);
    }

    /// Force-expire current hunt
    public entry fun expire_hunt(
        _admin: &AdminCap,
        game: &mut GameState,
    ) {
        if (game.hunt_active) {
            game.hunt_active = false;
            event::emit(HuntExpired { epoch: game.current_epoch });
        };
    }

    // ============ Player Functions ============

    fun build_claim_ticket_message(
        player: address,
        epoch: u64,
        ball_index: u64,
        assembly_id: address,
        ticket_expires_at_ms: u64,
        ticket_nonce: u64,
    ): vector<u8> {
        let mut bytes = b"SINGUHUNT_CLAIM_V1";
        vector::append(&mut bytes, bcs::to_bytes(&player));
        vector::append(&mut bytes, bcs::to_bytes(&epoch));
        vector::append(&mut bytes, bcs::to_bytes(&ball_index));
        vector::append(&mut bytes, bcs::to_bytes(&assembly_id));
        vector::append(&mut bytes, bcs::to_bytes(&ticket_expires_at_ms));
        vector::append(&mut bytes, bcs::to_bytes(&ticket_nonce));
        bytes
    }

    fun claim_ticket_key(message: &vector<u8>): address {
        sui::address::from_bytes(hash::blake2b256(message))
    }

    fun build_deliver_ticket_message(
        player: address,
        epoch: u64,
        ball_index: u64,
        assembly_id: address,
        ticket_expires_at_ms: u64,
        ticket_nonce: u64,
    ): vector<u8> {
        let mut bytes = b"SINGUHUNT_DELIVER_V1";
        vector::append(&mut bytes, bcs::to_bytes(&player));
        vector::append(&mut bytes, bcs::to_bytes(&epoch));
        vector::append(&mut bytes, bcs::to_bytes(&ball_index));
        vector::append(&mut bytes, bcs::to_bytes(&assembly_id));
        vector::append(&mut bytes, bcs::to_bytes(&ticket_expires_at_ms));
        vector::append(&mut bytes, bcs::to_bytes(&ticket_nonce));
        bytes
    }

    fun build_decrypt_ticket_message(
        player: address,
        epoch: u64,
        ticket_expires_at_ms: u64,
        ticket_nonce: u64,
    ): vector<u8> {
        let mut bytes = b"SINGUHUNT_DECRYPT_V1";
        vector::append(&mut bytes, bcs::to_bytes(&player));
        vector::append(&mut bytes, bcs::to_bytes(&epoch));
        vector::append(&mut bytes, bcs::to_bytes(&ticket_expires_at_ms));
        vector::append(&mut bytes, bcs::to_bytes(&ticket_nonce));
        bytes
    }

    /// Collect a dragon ball at a gate (first come, first served) using a
    /// short-lived ticket issued after the backend verifies trusted assembly context.
    public entry fun collect_ball(
        game: &mut GameState,
        ball_index: u64,
        assembly_id: address,
        ticket_expires_at_ms: u64,
        ticket_nonce: u64,
        ticket_signature: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        let now = clock::timestamp_ms(clock);
        let player = ctx.sender();
        let epoch = game.current_epoch;

        assert!(game.hunt_active, E_HUNT_NOT_ACTIVE);
        assert!(now <= game.hunt_end_time, E_HUNT_EXPIRED);
        assert!(ball_index < game.ball_gates.length(), E_INVALID_BALL);
        assert!(game.ticket_signer != @0x0, E_TICKET_SIGNER_NOT_SET);
        assert!(now <= ticket_expires_at_ms, E_TICKET_EXPIRED);

        // Check the verified assembly matches the configured gate.
        let gate = &game.ball_gates[ball_index];
        assert!(gate.gate_id == assembly_id, E_ASSEMBLY_MISMATCH);

        let claim_message = build_claim_ticket_message(
            player,
            epoch,
            ball_index,
            assembly_id,
            ticket_expires_at_ms,
            ticket_nonce,
        );
        let ticket_key = claim_ticket_key(&claim_message);
        assert!(!game.used_claim_tickets.contains(ticket_key), E_TICKET_REPLAY);
        assert!(
            sig_verify::verify_personal_message_signature(
                claim_message,
                ticket_signature,
                game.ticket_signer,
            ),
            E_INVALID_TICKET,
        );
        game.used_claim_tickets.add(ticket_key, true);

        let hunt_mode = get_hunt_mode(game);
        if (hunt_mode == MODE_TEAM_RACE) {
            assert!(
                dynamic_field::exists_(&game.id, TeamAssignmentKey { epoch, player }),
                E_TEAM_ASSIGNMENT_MISSING,
            );

            let assignment = *dynamic_field::borrow<TeamAssignmentKey, TeamAssignment>(
                &game.id,
                TeamAssignmentKey { epoch, player },
            );
            assert!(assignment.active, E_TEAM_REGISTRATION_CANCELLED);
            assert!(
                !dynamic_field::exists_(
                    &game.id,
                    TeamGateClaimKey {
                        epoch,
                        team_id: assignment.team_id,
                        ball_index,
                    },
                ),
                E_TEAM_GATE_ALREADY_CLAIMED,
            );

            dynamic_field::add(
                &mut game.id,
                TeamGateClaimKey {
                    epoch,
                    team_id: assignment.team_id,
                    ball_index,
                },
                player,
            );

            let roster = dynamic_field::borrow_mut<TeamRosterKey, TeamRoster>(
                &mut game.id,
                TeamRosterKey {
                    epoch,
                    team_id: assignment.team_id,
                },
            );
            roster.completed_count = roster.completed_count + 1;

            let collections = game.epoch_collections.borrow_mut(epoch);
            if (collections.contains(player)) {
                let count = collections.borrow_mut(player);
                *count = *count + 1;
            } else {
                collections.add(player, 1);
            };

            event::emit(TeamGateCompleted {
                epoch,
                team_id: assignment.team_id,
                star_index: ball_index,
                player,
            });
        } else {
            assert!(!gate.ball_collected, E_BALL_ALREADY_TAKEN);

            // Mark as collected
            let gate_mut = &mut game.ball_gates[ball_index];
            gate_mut.ball_collected = true;
            gate_mut.collector = player;

            let gate_id = gate_mut.gate_id;
            let gate_name = gate_mut.name;

            // Track player's collection count
            let collections = game.epoch_collections.borrow_mut(epoch);
            if (collections.contains(player)) {
                let count = collections.borrow_mut(player);
                *count = *count + 1;
            } else {
                collections.add(player, 1);
            };

            // Mint dragon ball token
            let ball = DragonBall {
                id: object::new(ctx),
                epoch,
                star_index: ball_index,
                gate_id,
                gate_name,
                expires_at: game.hunt_end_time,
                collector: player,
                delivered: false,
                delivered_at: 0,
            };

            event::emit(DragonBallCollected {
                epoch,
                star_index: ball_index,
                collector: player,
                gate_id,
            });

            transfer::transfer(ball, player);
        };
    }

    public entry fun deliver_ball(
        game: &mut GameState,
        ball: &mut DragonBall,
        assembly_id: address,
        ticket_expires_at_ms: u64,
        ticket_nonce: u64,
        ticket_signature: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        let now = clock::timestamp_ms(clock);
        let player = ctx.sender();
        let epoch = game.current_epoch;

        assert!(game.hunt_active, E_HUNT_NOT_ACTIVE);
        assert!(now <= game.hunt_end_time, E_HUNT_EXPIRED);
        assert!(game.ticket_signer != @0x0, E_TICKET_SIGNER_NOT_SET);
        assert!(now <= ticket_expires_at_ms, E_TICKET_EXPIRED);
        assert!(assembly_id == game.end_gate, E_INVALID_DELIVER_GATE);
        assert!(ball.epoch == epoch, E_INVALID_BALL);
        assert!(ball.collector == player, E_NOT_TOKEN_OWNER);
        assert!(!ball.delivered, E_ALREADY_DELIVERED);
        assert!(ball.star_index < game.ball_gates.length(), E_INVALID_BALL);

        let deliver_message = build_deliver_ticket_message(
            player,
            epoch,
            ball.star_index,
            assembly_id,
            ticket_expires_at_ms,
            ticket_nonce,
        );
        let ticket_key = claim_ticket_key(&deliver_message);
        assert!(!game.used_claim_tickets.contains(ticket_key), E_DELIVER_TICKET_REPLAY);
        assert!(
            sig_verify::verify_personal_message_signature(
                deliver_message,
                ticket_signature,
                game.ticket_signer,
            ),
            E_INVALID_TICKET,
        );
        game.used_claim_tickets.add(ticket_key, true);

        let gate = &mut game.ball_gates[ball.star_index];
        assert!(gate.gate_id == ball.gate_id, E_ASSEMBLY_MISMATCH);
        assert!(gate.ball_collected, E_INVALID_BALL);
        assert!(gate.collector == player, E_NOT_TOKEN_OWNER);
        assert!(!gate.ball_delivered, E_ALREADY_DELIVERED);

        gate.ball_delivered = true;
        gate.deliverer = player;
        ball.delivered = true;
        ball.delivered_at = now;

        event::emit(DragonBallDelivered {
            epoch,
            star_index: ball.star_index,
            deliverer: player,
            gate_id: assembly_id,
        });

        let mut delivered_count: u64 = 0;
        let mut i: u64 = 0;
        while (i < game.ball_gates.length()) {
            if (game.ball_gates[i].ball_delivered) {
                delivered_count = delivered_count + 1;
            };
            i = i + 1;
        };

        if (delivered_count == game.required_singu_count) {
            event::emit(HuntCompleted { epoch });
        };
    }

    fun mint_achievement_to(
        game: &mut GameState,
        owner: address,
        epoch: u64,
        now: u64,
        name: vector<u8>,
        description: vector<u8>,
        ctx: &mut TxContext,
    ) {
        assert!(
            !dynamic_field::exists_(&game.id, EpochAchievementClaimKey { epoch, player: owner }),
            E_ALREADY_HAS_ACHIEVEMENT,
        );
        game.total_achievements = game.total_achievements + 1;
        let achievement_number = game.total_achievements;
        let achievement = AchievementNFT {
            id: object::new(ctx),
            completed_epoch: epoch,
            earned_at: now,
            owner,
            achievement_number,
            name,
            description,
            image_url: ACHIEVEMENT_IMAGE_URL,
        };
        dynamic_field::add(&mut game.id, EpochAchievementClaimKey { epoch, player: owner }, true);
        event::emit(AchievementEarned {
            epoch,
            player: owner,
            achievement_number,
        });

        transfer::transfer(achievement, owner);
    }

    public entry fun claim_decrypt_achievement(
        game: &mut GameState,
        ticket_expires_at_ms: u64,
        ticket_nonce: u64,
        ticket_signature: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        let now = clock::timestamp_ms(clock);
        let player = ctx.sender();
        let epoch = game.current_epoch;

        assert!(game.hunt_active, E_HUNT_NOT_ACTIVE);
        assert!(now <= game.hunt_end_time, E_HUNT_EXPIRED);
        assert!(get_hunt_mode(game) == MODE_DEEP_DECRYPT, E_INVALID_MODE);
        assert!(game.ticket_signer != @0x0, E_TICKET_SIGNER_NOT_SET);
        assert!(now <= ticket_expires_at_ms, E_TICKET_EXPIRED);
        assert!(
            dynamic_field::exists_(&game.id, RegPlayerKey { epoch, player }),
            E_NOT_REGISTERED,
        );
        assert!(
            !dynamic_field::exists_(&game.id, EpochAchievementClaimKey { epoch, player }),
            E_ALREADY_HAS_ACHIEVEMENT,
        );

        let decrypt_message = build_decrypt_ticket_message(
            player,
            epoch,
            ticket_expires_at_ms,
            ticket_nonce,
        );
        let ticket_key = claim_ticket_key(&decrypt_message);
        assert!(!game.used_claim_tickets.contains(ticket_key), E_TICKET_REPLAY);
        assert!(
            sig_verify::verify_personal_message_signature(
                decrypt_message,
                ticket_signature,
                game.ticket_signer,
            ),
            E_INVALID_TICKET,
        );
        game.used_claim_tickets.add(ticket_key, true);

        let winner_slots = get_winner_slots(game, epoch);
        let winner_rank = {
            let winner_count_ref = dynamic_field::borrow_mut<WinnerCountKey, u64>(
                &mut game.id,
                WinnerCountKey { epoch },
            );
            assert!(*winner_count_ref < winner_slots, E_ALL_WINNER_SLOTS_FILLED);
            *winner_count_ref = *winner_count_ref + 1;
            *winner_count_ref
        };

        if (!dynamic_field::exists_(&game.id, EpochWinnerKey { epoch })) {
            dynamic_field::add(&mut game.id, EpochWinnerKey { epoch }, player);
        };

        mint_achievement_to(
            game,
            player,
            epoch,
            now,
            b"Singu Hunt award - Deep Decrypt",
            b"Awarded to the fastest Deep Decrypt solvers who answered the daily official-history puzzle correctly.",
            ctx,
        );

        event::emit(DeepDecryptSolved {
            epoch,
            player,
            winner_rank,
        });
    }

    public entry fun claim_team_achievement(
        game: &mut GameState,
        assembly_id: address,
        ticket_expires_at_ms: u64,
        ticket_nonce: u64,
        ticket_signature: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        let now = clock::timestamp_ms(clock);
        let player = ctx.sender();
        let epoch = game.current_epoch;

        assert!(game.hunt_active, E_HUNT_NOT_ACTIVE);
        assert!(now <= game.hunt_end_time, E_HUNT_EXPIRED);
        assert!(get_hunt_mode(game) == MODE_TEAM_RACE, E_NOT_TEAM_MODE);
        assert!(game.ticket_signer != @0x0, E_TICKET_SIGNER_NOT_SET);
        assert!(now <= ticket_expires_at_ms, E_TICKET_EXPIRED);
        assert!(assembly_id == game.end_gate, E_INVALID_DELIVER_GATE);
        assert!(
            dynamic_field::exists_(&game.id, TeamAssignmentKey { epoch, player }),
            E_TEAM_ASSIGNMENT_MISSING,
        );

        let deliver_message = build_deliver_ticket_message(
            player,
            epoch,
            0,
            assembly_id,
            ticket_expires_at_ms,
            ticket_nonce,
        );
        let ticket_key = claim_ticket_key(&deliver_message);
        assert!(!game.used_claim_tickets.contains(ticket_key), E_DELIVER_TICKET_REPLAY);
        assert!(
            sig_verify::verify_personal_message_signature(
                deliver_message,
                ticket_signature,
                game.ticket_signer,
            ),
            E_INVALID_TICKET,
        );
        game.used_claim_tickets.add(ticket_key, true);

        let assignment = *dynamic_field::borrow<TeamAssignmentKey, TeamAssignment>(
            &game.id,
            TeamAssignmentKey { epoch, player },
        );
        assert!(assignment.active, E_TEAM_REGISTRATION_CANCELLED);
        let winner_slots = get_winner_slots(game, epoch);

        let (member_1, member_2, member_3) = {
            let roster = dynamic_field::borrow<TeamRosterKey, TeamRoster>(
                &game.id,
                TeamRosterKey {
                    epoch,
                    team_id: assignment.team_id,
                },
            );
            assert!(roster.completed_count == game.required_singu_count, E_TEAM_INCOMPLETE);
            assert!(!roster.finished, E_TEAM_ALREADY_FINISHED);
            (roster.member_1, roster.member_2, roster.member_3)
        };

        let winner_rank = {
            let winner_count_ref = dynamic_field::borrow_mut<WinnerCountKey, u64>(
                &mut game.id,
                WinnerCountKey { epoch },
            );
            assert!(*winner_count_ref < winner_slots, E_ALL_WINNER_SLOTS_FILLED);
            *winner_count_ref = *winner_count_ref + 1;
            *winner_count_ref
        };

        {
            let roster = dynamic_field::borrow_mut<TeamRosterKey, TeamRoster>(
                &mut game.id,
                TeamRosterKey {
                    epoch,
                    team_id: assignment.team_id,
                },
            );
            roster.finished = true;
            roster.winner_rank = winner_rank;
            roster.finished_at = now;
        };

        if (!dynamic_field::exists_(&game.id, EpochWinnerKey { epoch })) {
            dynamic_field::add(&mut game.id, EpochWinnerKey { epoch }, player);
        };

        let nft_name = b"Singu Hunt award - Team Race";
        let nft_description = b"Awarded to every member of a winning Team Race squad that completed all checkpoints and returned to base in time.";

        mint_achievement_to(game, member_1, epoch, now, nft_name, nft_description, ctx);
        mint_achievement_to(game, member_2, epoch, now, nft_name, nft_description, ctx);
        mint_achievement_to(game, member_3, epoch, now, nft_name, nft_description, ctx);

        event::emit(TeamFinished {
            epoch,
            team_id: assignment.team_id,
            finisher: player,
            winner_rank,
        });
    }

    /// Deposit the required number of Singu at the end gate to claim achievement.
    public entry fun claim_achievement(
        game: &mut GameState,
        mut balls: vector<DragonBall>,
        clock: &Clock,
        ctx: &mut TxContext,
    ) {
        let now = clock::timestamp_ms(clock);
        let player = ctx.sender();
        let epoch = game.current_epoch;
        assert!(get_hunt_mode(game) != MODE_TEAM_RACE, E_NOT_TEAM_MODE);

        assert!(game.hunt_active, E_HUNT_NOT_ACTIVE);
        assert!(now <= game.hunt_end_time, E_HUNT_EXPIRED);
        assert!(balls.length() == game.required_singu_count, E_INCOMPLETE_COLLECTION);

        // Check registration (if registration was used for this epoch)
        if (dynamic_field::exists_(&game.id, RegCountKey { epoch })) {
            assert!(
                dynamic_field::exists_(&game.id, RegPlayerKey { epoch, player }),
                E_NOT_REGISTERED,
            );
        };

        // Check winner slots: only top N% can claim (N=5 for Solo Race)
        if (dynamic_field::exists_(&game.id, WinnerSlotsKey { epoch })) {
            let winner_slots = *dynamic_field::borrow<WinnerSlotsKey, u64>(&game.id, WinnerSlotsKey { epoch });
            let winner_count = *dynamic_field::borrow<WinnerCountKey, u64>(&game.id, WinnerCountKey { epoch });
            assert!(winner_count < winner_slots, E_ALL_WINNER_SLOTS_FILLED);
        };

        // Verify all required balls, current epoch, owned by player, and unique by index.
        let mut i: u64 = 0;

        while (i < balls.length()) {
            let ball = &balls[i];
            assert!(ball.epoch == epoch, E_INCOMPLETE_COLLECTION);
            assert!(ball.collector == player, E_NOT_TOKEN_OWNER);
            assert!(ball.delivered, E_BALL_NOT_DELIVERED);

            let mut j: u64 = i + 1;
            while (j < balls.length()) {
                let other_ball = &balls[j];
                assert!(ball.star_index != other_ball.star_index, E_INCOMPLETE_COLLECTION);
                j = j + 1;
            };
            i = i + 1;
        };

        // Burn all required balls
        let mut j: u64 = 0;
        while (j < game.required_singu_count) {
            let ball = balls.pop_back();
            let DragonBall { id, epoch: e, star_index: si, gate_id: _, gate_name: _, expires_at: _, collector: _, delivered: _, delivered_at: _ } = ball;
            event::emit(DragonBallBurned { epoch: e, star_index: si, burner: player });
            object::delete(id);
            j = j + 1;
        };
        balls.destroy_empty();

        // Increment winner count for this epoch
        if (dynamic_field::exists_(&game.id, WinnerCountKey { epoch })) {
            let count = dynamic_field::borrow_mut<WinnerCountKey, u64>(&mut game.id, WinnerCountKey { epoch });
            *count = *count + 1;
        };

        // Record first winner address (for display)
        if (!dynamic_field::exists_(&game.id, EpochWinnerKey { epoch })) {
            dynamic_field::add(&mut game.id, EpochWinnerKey { epoch }, player);
        };

        mint_achievement_to(
            game,
            player,
            epoch,
            now,
            b"Singu Hunt award - Solo Race",
            b"First hunter to collect and deliver all required Singu in this session. A one-of-a-kind achievement per epoch.",
            ctx,
        );
    }

    /// Burn expired dragon ball
    public entry fun burn_expired_ball(
        ball: DragonBall,
        clock: &Clock,
    ) {
        let now = clock::timestamp_ms(clock);
        assert!(now > ball.expires_at, E_HUNT_NOT_ACTIVE);
        let DragonBall { id, epoch, star_index, gate_id: _, gate_name: _, expires_at: _, collector, delivered: _, delivered_at: _ } = ball;
        event::emit(DragonBallBurned { epoch, star_index, burner: collector });
        object::delete(id);
    }

    // ============ View Functions ============

    public fun get_hunt_info(game: &GameState): (u64, u64, u64, bool) {
        (game.current_epoch, game.hunt_start_time, game.hunt_end_time, game.hunt_active)
    }

    public fun get_start_gate(game: &GameState): (address, vector<u8>) {
        (game.start_gate, game.start_gate_name)
    }

    public fun get_end_gate(game: &GameState): (address, vector<u8>) {
        (game.end_gate, game.end_gate_name)
    }

    public fun get_ball_gates(game: &GameState): &vector<GateLocation> {
        &game.ball_gates
    }

    public fun get_total_achievements(game: &GameState): u64 {
        game.total_achievements
    }

    /// Returns the current hunt mode (1-5). Defaults to MODE_SOLO_RACE if not set.
    public fun get_hunt_mode(game: &GameState): u8 {
        if (dynamic_field::exists_(&game.id, HuntModeKey {})) {
            *dynamic_field::borrow(&game.id, HuntModeKey {})
        } else {
            MODE_SOLO_RACE
        }
    }

    /// Check if an epoch already has a winner. Returns true if someone has claimed achievement for that epoch.
    public fun has_epoch_winner(game: &GameState, epoch: u64): bool {
        dynamic_field::exists_(&game.id, EpochWinnerKey { epoch })
    }

    /// Get the winner address for a given epoch. Aborts if no winner yet.
    public fun get_epoch_winner(game: &GameState, epoch: u64): address {
        *dynamic_field::borrow(&game.id, EpochWinnerKey { epoch })
    }

    /// Check if registration is currently open.
    public fun is_registration_open(game: &GameState): bool {
        if (dynamic_field::exists_(&game.id, RegPhaseKey {})) {
            *dynamic_field::borrow<RegPhaseKey, bool>(&game.id, RegPhaseKey {})
        } else {
            false
        }
    }

    /// Get registration count for an epoch.
    public fun get_reg_count(game: &GameState, epoch: u64): u64 {
        load_reg_count(game, epoch)
    }

    /// Check if a player is registered for an epoch.
    public fun is_player_registered(game: &GameState, epoch: u64, player: address): bool {
        dynamic_field::exists_(&game.id, RegPlayerKey { epoch, player })
    }

    /// Get winner slots for an epoch.
    public fun get_winner_slots(game: &GameState, epoch: u64): u64 {
        if (dynamic_field::exists_(&game.id, WinnerSlotsKey { epoch })) {
            *dynamic_field::borrow<WinnerSlotsKey, u64>(&game.id, WinnerSlotsKey { epoch })
        } else {
            1
        }
    }

    /// Get current winner count for an epoch.
    public fun get_winner_count(game: &GameState, epoch: u64): u64 {
        if (dynamic_field::exists_(&game.id, WinnerCountKey { epoch })) {
            *dynamic_field::borrow<WinnerCountKey, u64>(&game.id, WinnerCountKey { epoch })
        } else {
            0
        }
    }

    public fun get_successful_reg_count(game: &GameState, epoch: u64): u64 {
        if (dynamic_field::exists_(&game.id, SuccessfulRegCountKey { epoch })) {
            *dynamic_field::borrow<SuccessfulRegCountKey, u64>(&game.id, SuccessfulRegCountKey { epoch })
        } else {
            0
        }
    }

    public fun registration_fee_for_mode(mode: u8): u64 {
        if (mode == MODE_SOLO_RACE) {
            REG_FEE_SOLO_RACE
        } else if (mode == MODE_TEAM_RACE) {
            REG_FEE_TEAM_RACE
        } else if (mode == MODE_DEEP_DECRYPT) {
            REG_FEE_DEEP_DECRYPT
        } else if (mode == MODE_LARGE_ARENA) {
            REG_FEE_LARGE_ARENA
        } else {
            REG_FEE_OBSTACLE_RUN
        }
    }

    public fun total_lux_collected(game: &GameState): u64 {
        game.total_lux_collected
    }

    public fun registration_fee_pool_balance(game: &GameState): u64 {
        balance::value(&game.registration_fee_pool)
    }

    public fun get_team_count(game: &GameState, epoch: u64): u64 {
        load_team_count(game, epoch)
    }
}

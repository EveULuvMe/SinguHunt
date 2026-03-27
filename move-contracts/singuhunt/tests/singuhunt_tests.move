#[test_only]
module singuhunt::singuhunt_tests;

use sui::clock::Clock;
use sui::test_scenario;
use sui::token::Token;

use singuhunt::achievement_token::{Self as achievement_token, AchievementTreasury};
use singuhunt::singu_shard_token::{Self as singu_shard_token, SINGU_SHARD_TOKEN, SinguShardTreasury};
use singuhunt::singuhunt;
use singuhunt::singuhunt::{AdminCap, GameState, SinguShardRecord};

const ADMIN: address = @0xA;
const PLAYER: address = @0xB;
const PLAYER_2: address = @0xC;
const PLAYER_3: address = @0xD;

#[test]
fun test_registration_fees_cover_all_five_modes() {
    assert!(singuhunt::registration_fee_for_mode(1) == 12_000_000_000, 0);
    assert!(singuhunt::registration_fee_for_mode(2) == 15_000_000_000, 1);
    assert!(singuhunt::registration_fee_for_mode(3) == 30_000_000_000, 2);
    assert!(singuhunt::registration_fee_for_mode(4) == 22_000_000_000, 3);
    assert!(singuhunt::registration_fee_for_mode(5) == 18_000_000_000, 4);
}

#[test]
fun test_solo_race_claim_path() {
    let mut scenario = test_scenario::begin(ADMIN);
    test_scenario::create_system_objects(&mut scenario);
    {
        let ctx = test_scenario::ctx(&mut scenario);
        let admin = singuhunt::new_admin_for_testing(ctx);
        let mut game = singuhunt::make_game_for_testing(ctx);
        singuhunt::configure_basic_game(&admin, &mut game);
        let shard_treasury = singu_shard_token::new_for_testing(ctx);
        let achievement_treasury = achievement_token::new_for_testing(ctx);
        singuhunt::transfer_admin_for_testing(admin, ADMIN);
        singu_shard_token::transfer_for_testing(shard_treasury, PLAYER);
        achievement_token::transfer_for_testing(achievement_treasury, PLAYER);
        singuhunt::share_game_for_testing(game);
    };

    test_scenario::next_tx(&mut scenario, ADMIN);
    {
        let admin = test_scenario::take_from_sender<AdminCap>(&scenario);
        let mut game = test_scenario::take_shared<GameState>(&scenario);
        let mut clock = test_scenario::take_shared<Clock>(&scenario);
        sui::clock::set_for_testing(&mut clock, 1_000);
        singuhunt::start_hunt_with_selection(
            &admin,
            &mut game,
            vector[0, 1],
            1,
            10_000,
            &clock,
            test_scenario::ctx(&mut scenario),
        );
        test_scenario::return_to_sender(&scenario, admin);
        test_scenario::return_shared(game);
        test_scenario::return_shared(clock);
    };

    test_scenario::next_tx(&mut scenario, PLAYER);
    {
        let mut game = test_scenario::take_shared<GameState>(&scenario);
        let mut clock = test_scenario::take_shared<Clock>(&scenario);
        let mut shard_treasury = test_scenario::take_from_sender<SinguShardTreasury>(&scenario);
        let mut achievement_treasury = test_scenario::take_from_sender<AchievementTreasury>(&scenario);
        sui::clock::set_for_testing(&mut clock, 2_000);
        let (records, tokens) = singuhunt::make_delivered_shards(
            &mut shard_treasury,
            PLAYER,
            1,
            test_scenario::ctx(&mut scenario),
        );
        singuhunt::claim_achievement(
            &mut game,
            &mut shard_treasury,
            &mut achievement_treasury,
            records,
            tokens,
            &clock,
            test_scenario::ctx(&mut scenario),
        );
        assert!(singuhunt::get_hunt_mode(&game) == 1, 10);
        assert!(singuhunt::get_total_achievements(&game) == 1, 11);
        assert!(singuhunt::get_winner_count(&game, 1) == 1, 12);
        test_scenario::return_to_sender(&scenario, shard_treasury);
        test_scenario::return_to_sender(&scenario, achievement_treasury);
        test_scenario::return_shared(game);
        test_scenario::return_shared(clock);
    };
    let _ = test_scenario::end(scenario);
}

#[test]
fun test_large_arena_claim_path() {
    let mut scenario = test_scenario::begin(ADMIN);
    test_scenario::create_system_objects(&mut scenario);
    {
        let ctx = test_scenario::ctx(&mut scenario);
        let admin = singuhunt::new_admin_for_testing(ctx);
        let mut game = singuhunt::make_game_for_testing(ctx);
        singuhunt::configure_basic_game(&admin, &mut game);
        let shard_treasury = singu_shard_token::new_for_testing(ctx);
        let achievement_treasury = achievement_token::new_for_testing(ctx);
        singuhunt::transfer_admin_for_testing(admin, ADMIN);
        singu_shard_token::transfer_for_testing(shard_treasury, PLAYER);
        achievement_token::transfer_for_testing(achievement_treasury, PLAYER);
        singuhunt::share_game_for_testing(game);
    };

    test_scenario::next_tx(&mut scenario, ADMIN);
    {
        let admin = test_scenario::take_from_sender<AdminCap>(&scenario);
        let mut game = test_scenario::take_shared<GameState>(&scenario);
        let mut clock = test_scenario::take_shared<Clock>(&scenario);
        sui::clock::set_for_testing(&mut clock, 1_000);
        singuhunt::start_hunt_with_selection(
            &admin,
            &mut game,
            vector[0, 1],
            4,
            10_000,
            &clock,
            test_scenario::ctx(&mut scenario),
        );
        test_scenario::return_to_sender(&scenario, admin);
        test_scenario::return_shared(game);
        test_scenario::return_shared(clock);
    };

    test_scenario::next_tx(&mut scenario, PLAYER);
    {
        let mut game = test_scenario::take_shared<GameState>(&scenario);
        let mut clock = test_scenario::take_shared<Clock>(&scenario);
        let mut shard_treasury = test_scenario::take_from_sender<SinguShardTreasury>(&scenario);
        let mut achievement_treasury = test_scenario::take_from_sender<AchievementTreasury>(&scenario);
        sui::clock::set_for_testing(&mut clock, 2_000);
        let (records, tokens) = singuhunt::make_delivered_shards(
            &mut shard_treasury,
            PLAYER,
            1,
            test_scenario::ctx(&mut scenario),
        );
        singuhunt::claim_achievement(
            &mut game,
            &mut shard_treasury,
            &mut achievement_treasury,
            records,
            tokens,
            &clock,
            test_scenario::ctx(&mut scenario),
        );
        assert!(singuhunt::get_hunt_mode(&game) == 4, 20);
        assert!(singuhunt::get_total_achievements(&game) == 1, 21);
        test_scenario::return_to_sender(&scenario, shard_treasury);
        test_scenario::return_to_sender(&scenario, achievement_treasury);
        test_scenario::return_shared(game);
        test_scenario::return_shared(clock);
    };
    let _ = test_scenario::end(scenario);
}

#[test]
fun test_obstacle_run_sequential_collection_and_claim() {
    let mut scenario = test_scenario::begin(ADMIN);
    test_scenario::create_system_objects(&mut scenario);
    {
        let ctx = test_scenario::ctx(&mut scenario);
        let admin = singuhunt::new_admin_for_testing(ctx);
        let mut game = singuhunt::make_game_for_testing(ctx);
        singuhunt::configure_basic_game(&admin, &mut game);
        let shard_treasury = singu_shard_token::new_for_testing(ctx);
        let achievement_treasury = achievement_token::new_for_testing(ctx);
        singuhunt::transfer_admin_for_testing(admin, ADMIN);
        singu_shard_token::transfer_for_testing(shard_treasury, PLAYER);
        achievement_token::transfer_for_testing(achievement_treasury, PLAYER);
        singuhunt::share_game_for_testing(game);
    };

    test_scenario::next_tx(&mut scenario, ADMIN);
    {
        let admin = test_scenario::take_from_sender<AdminCap>(&scenario);
        let mut game = test_scenario::take_shared<GameState>(&scenario);
        let mut clock = test_scenario::take_shared<Clock>(&scenario);
        sui::clock::set_for_testing(&mut clock, 1_000);
        singuhunt::start_hunt_with_selection(
            &admin,
            &mut game,
            vector[0, 1],
            5,
            10_000,
            &clock,
            test_scenario::ctx(&mut scenario),
        );
        test_scenario::return_to_sender(&scenario, admin);
        test_scenario::return_shared(game);
        test_scenario::return_shared(clock);
    };

    test_scenario::next_tx(&mut scenario, PLAYER);
    {
        let mut game = test_scenario::take_shared<GameState>(&scenario);
        let mut clock = test_scenario::take_shared<Clock>(&scenario);
        let mut shard_treasury = test_scenario::take_from_sender<SinguShardTreasury>(&scenario);
        sui::clock::set_for_testing(&mut clock, 2_000);
        singuhunt::collect_singu_shard_for_testing(
            &mut game,
            &mut shard_treasury,
            0,
            @0x31,
            &clock,
            test_scenario::ctx(&mut scenario),
        );
        singuhunt::collect_singu_shard_for_testing(
            &mut game,
            &mut shard_treasury,
            1,
            @0x32,
            &clock,
            test_scenario::ctx(&mut scenario),
        );
        assert!(singuhunt::get_epoch_collection_count_for_testing(&game, 1, PLAYER) == 2, 30);
        test_scenario::return_to_sender(&scenario, shard_treasury);
        test_scenario::return_shared(game);
        test_scenario::return_shared(clock);
    };

    test_scenario::next_tx(&mut scenario, PLAYER);
    {
        let mut game = test_scenario::take_shared<GameState>(&scenario);
        let clock = test_scenario::take_shared<Clock>(&scenario);
        let mut shard_treasury = test_scenario::take_from_sender<SinguShardTreasury>(&scenario);
        let mut achievement_treasury = test_scenario::take_from_sender<AchievementTreasury>(&scenario);
        let mut record_1 = test_scenario::take_from_sender<SinguShardRecord>(&scenario);
        let mut record_2 = test_scenario::take_from_sender<SinguShardRecord>(&scenario);
        let token_1 = test_scenario::take_from_sender<Token<SINGU_SHARD_TOKEN>>(&scenario);
        let token_2 = test_scenario::take_from_sender<Token<SINGU_SHARD_TOKEN>>(&scenario);
        singuhunt::mark_record_delivered_for_testing(&mut record_1, 3_000);
        singuhunt::mark_record_delivered_for_testing(&mut record_2, 3_000);
        singuhunt::claim_achievement(
            &mut game,
            &mut shard_treasury,
            &mut achievement_treasury,
            vector[record_1, record_2],
            vector[token_1, token_2],
            &clock,
            test_scenario::ctx(&mut scenario),
        );
        assert!(singuhunt::get_hunt_mode(&game) == 5, 31);
        assert!(singuhunt::get_total_achievements(&game) == 1, 32);
        test_scenario::return_to_sender(&scenario, shard_treasury);
        test_scenario::return_to_sender(&scenario, achievement_treasury);
        test_scenario::return_shared(game);
        test_scenario::return_shared(clock);
    };
    let _ = test_scenario::end(scenario);
}

#[test]
fun test_deep_decrypt_claim_path() {
    let mut scenario = test_scenario::begin(ADMIN);
    test_scenario::create_system_objects(&mut scenario);
    {
        let ctx = test_scenario::ctx(&mut scenario);
        let admin = singuhunt::new_admin_for_testing(ctx);
        let mut game = singuhunt::make_game_for_testing(ctx);
        singuhunt::configure_basic_game(&admin, &mut game);
        let achievement_treasury = achievement_token::new_for_testing(ctx);
        singuhunt::transfer_admin_for_testing(admin, ADMIN);
        achievement_token::transfer_for_testing(achievement_treasury, PLAYER);
        singuhunt::share_game_for_testing(game);
    };

    test_scenario::next_tx(&mut scenario, ADMIN);
    {
        let admin = test_scenario::take_from_sender<AdminCap>(&scenario);
        let mut game = test_scenario::take_shared<GameState>(&scenario);
        let mut clock = test_scenario::take_shared<Clock>(&scenario);
        sui::clock::set_for_testing(&mut clock, 1_000);
        singuhunt::start_hunt_with_selection(
            &admin,
            &mut game,
            vector[0, 1],
            3,
            10_000,
            &clock,
            test_scenario::ctx(&mut scenario),
        );
        test_scenario::return_to_sender(&scenario, admin);
        test_scenario::return_shared(game);
        test_scenario::return_shared(clock);
    };

    test_scenario::next_tx(&mut scenario, PLAYER);
    {
        let mut game = test_scenario::take_shared<GameState>(&scenario);
        let mut clock = test_scenario::take_shared<Clock>(&scenario);
        let mut achievement_treasury = test_scenario::take_from_sender<AchievementTreasury>(&scenario);
        singuhunt::seed_registered_player_for_testing(&mut game, 1, PLAYER);
        sui::clock::set_for_testing(&mut clock, 2_000);
        singuhunt::claim_decrypt_achievement_for_testing(
            &mut game,
            &mut achievement_treasury,
            &clock,
            test_scenario::ctx(&mut scenario),
        );
        assert!(singuhunt::get_hunt_mode(&game) == 3, 40);
        assert!(singuhunt::get_total_achievements(&game) == 1, 41);
        assert!(singuhunt::has_epoch_winner(&game, 1), 42);
        test_scenario::return_to_sender(&scenario, achievement_treasury);
        test_scenario::return_shared(game);
        test_scenario::return_shared(clock);
    };
    let _ = test_scenario::end(scenario);
}

#[test]
fun test_team_race_finalize_collect_and_claim() {
    let mut scenario = test_scenario::begin(ADMIN);
    test_scenario::create_system_objects(&mut scenario);
    {
        let ctx = test_scenario::ctx(&mut scenario);
        let admin = singuhunt::new_admin_for_testing(ctx);
        let mut game = singuhunt::make_game_for_testing(ctx);
        singuhunt::configure_basic_game(&admin, &mut game);
        let shard_treasury = singu_shard_token::new_for_testing(ctx);
        let achievement_treasury = achievement_token::new_for_testing(ctx);
        singuhunt::transfer_admin_for_testing(admin, ADMIN);
        singu_shard_token::transfer_for_testing(shard_treasury, PLAYER);
        achievement_token::transfer_for_testing(achievement_treasury, PLAYER);
        singuhunt::share_game_for_testing(game);
    };

    test_scenario::next_tx(&mut scenario, ADMIN);
    {
        let admin = test_scenario::take_from_sender<AdminCap>(&scenario);
        let mut game = test_scenario::take_shared<GameState>(&scenario);
        let mut clock = test_scenario::take_shared<Clock>(&scenario);
        sui::clock::set_for_testing(&mut clock, 1_000);
        singuhunt::open_registration(&admin, &mut game, 2, 1_500, 2_000, &clock);
        singuhunt::seed_three_player_team_registration_for_testing(
            &mut game,
            1,
            PLAYER,
            PLAYER_2,
            PLAYER_3,
        );
        sui::clock::set_for_testing(&mut clock, 1_600);
        singuhunt::finalize_team_registration(&admin, &mut game, 7, &clock);
        singuhunt::start_hunt_with_selection(
            &admin,
            &mut game,
            vector[0, 1],
            2,
            10_000,
            &clock,
            test_scenario::ctx(&mut scenario),
        );
        assert!(singuhunt::get_team_count(&game, 1) == 1, 50);
        assert!(singuhunt::get_successful_reg_count(&game, 1) == 3, 51);
        test_scenario::return_to_sender(&scenario, admin);
        test_scenario::return_shared(game);
        test_scenario::return_shared(clock);
    };

    test_scenario::next_tx(&mut scenario, PLAYER);
    {
        let mut game = test_scenario::take_shared<GameState>(&scenario);
        let mut clock = test_scenario::take_shared<Clock>(&scenario);
        let mut shard_treasury = test_scenario::take_from_sender<SinguShardTreasury>(&scenario);
        let mut achievement_treasury = test_scenario::take_from_sender<AchievementTreasury>(&scenario);
        sui::clock::set_for_testing(&mut clock, 2_000);
        singuhunt::collect_singu_shard_for_testing(
            &mut game,
            &mut shard_treasury,
            0,
            @0x31,
            &clock,
            test_scenario::ctx(&mut scenario),
        );
        singuhunt::collect_singu_shard_for_testing(
            &mut game,
            &mut shard_treasury,
            1,
            @0x32,
            &clock,
            test_scenario::ctx(&mut scenario),
        );
        singuhunt::claim_team_achievement_for_testing(
            &mut game,
            &mut achievement_treasury,
            &clock,
            test_scenario::ctx(&mut scenario),
        );
        assert!(singuhunt::get_hunt_mode(&game) == 2, 52);
        assert!(singuhunt::get_total_achievements(&game) == 3, 53);
        assert!(singuhunt::get_winner_count(&game, 1) == 1, 54);
        test_scenario::return_to_sender(&scenario, shard_treasury);
        test_scenario::return_to_sender(&scenario, achievement_treasury);
        test_scenario::return_shared(game);
        test_scenario::return_shared(clock);
    };
    let _ = test_scenario::end(scenario);
}

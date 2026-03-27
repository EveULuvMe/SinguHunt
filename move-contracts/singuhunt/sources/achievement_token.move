module singuhunt::achievement_token {
    use sui::coin::{Self, TreasuryCap};
    use sui::token::{Self as token, Token};

    public struct ACHIEVEMENT_TOKEN has drop {}

    public struct AchievementTreasury has key {
        id: UID,
        cap: TreasuryCap<ACHIEVEMENT_TOKEN>,
    }

    fun init(witness: ACHIEVEMENT_TOKEN, ctx: &mut TxContext) {
        let (treasury_cap, metadata) = coin::create_currency(
            witness,
            0,
            b"AWARD",
            b"Singu Hunt Award",
            b"Closed-loop achievement token for Singu Hunt winners",
            option::none(),
            ctx,
        );

        transfer::share_object(AchievementTreasury {
            id: object::new(ctx),
            cap: treasury_cap,
        });
        transfer::public_freeze_object(metadata);
    }

    public(package) fun mint(
        treasury: &mut AchievementTreasury,
        amount: u64,
        ctx: &mut TxContext,
    ): Token<ACHIEVEMENT_TOKEN> {
        token::mint(&mut treasury.cap, amount, ctx)
    }

    public(package) fun value(award: &Token<ACHIEVEMENT_TOKEN>): u64 {
        token::value(award)
    }

    public(package) fun transfer_to_owner(
        treasury: &mut AchievementTreasury,
        award: Token<ACHIEVEMENT_TOKEN>,
        owner: address,
        ctx: &mut TxContext,
    ) {
        let req = token::transfer(award, owner, ctx);
        token::confirm_with_treasury_cap(&mut treasury.cap, req, ctx);
    }

    #[test_only]
    public fun new_for_testing(ctx: &mut TxContext): AchievementTreasury {
        let (treasury_cap, metadata) = coin::create_currency(
            ACHIEVEMENT_TOKEN {},
            0,
            b"AWARD",
            b"Singu Hunt Award",
            b"Closed-loop achievement token for Singu Hunt winners",
            option::none(),
            ctx,
        );
        transfer::public_freeze_object(metadata);
        AchievementTreasury {
            id: object::new(ctx),
            cap: treasury_cap,
        }
    }

    #[test_only]
    public fun transfer_for_testing(treasury: AchievementTreasury, owner: address) {
        transfer::transfer(treasury, owner)
    }
}

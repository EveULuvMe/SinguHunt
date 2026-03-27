module singuhunt::singu_shard_token {
    use sui::coin::{Self, TreasuryCap};
    use sui::token::{Self as token, Token};

    public struct SINGU_SHARD_TOKEN has drop {}

    public struct SinguShardTreasury has key {
        id: UID,
        cap: TreasuryCap<SINGU_SHARD_TOKEN>,
    }

    fun init(witness: SINGU_SHARD_TOKEN, ctx: &mut TxContext) {
        let (treasury_cap, metadata) = coin::create_currency(
            witness,
            0,
            b"SHARD",
            b"Singu Shard",
            b"Closed-loop gameplay shard for Singu Hunt",
            option::none(),
            ctx,
        );

        transfer::share_object(SinguShardTreasury {
            id: object::new(ctx),
            cap: treasury_cap,
        });
        transfer::public_freeze_object(metadata);
    }

    public(package) fun mint(
        treasury: &mut SinguShardTreasury,
        amount: u64,
        ctx: &mut TxContext,
    ): Token<SINGU_SHARD_TOKEN> {
        token::mint(&mut treasury.cap, amount, ctx)
    }

    public(package) fun value(shard: &Token<SINGU_SHARD_TOKEN>): u64 {
        token::value(shard)
    }

    public(package) fun transfer_to_owner(
        treasury: &mut SinguShardTreasury,
        shard: Token<SINGU_SHARD_TOKEN>,
        owner: address,
        ctx: &mut TxContext,
    ) {
        let req = token::transfer(shard, owner, ctx);
        token::confirm_with_treasury_cap(&mut treasury.cap, req, ctx);
    }

    public(package) fun burn(
        treasury: &mut SinguShardTreasury,
        shard: Token<SINGU_SHARD_TOKEN>,
        ctx: &mut TxContext,
    ) {
        let req = token::spend(shard, ctx);
        token::confirm_with_treasury_cap(&mut treasury.cap, req, ctx);
    }

    #[test_only]
    public fun new_for_testing(ctx: &mut TxContext): SinguShardTreasury {
        let (treasury_cap, metadata) = coin::create_currency(
            SINGU_SHARD_TOKEN {},
            0,
            b"SHARD",
            b"Singu Shard",
            b"Closed-loop gameplay shard for Singu Hunt",
            option::none(),
            ctx,
        );
        transfer::public_freeze_object(metadata);
        SinguShardTreasury {
            id: object::new(ctx),
            cap: treasury_cap,
        }
    }

    #[test_only]
    public fun transfer_for_testing(treasury: SinguShardTreasury, owner: address) {
        transfer::transfer(treasury, owner)
    }
}

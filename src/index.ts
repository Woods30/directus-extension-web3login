import { Action } from "@directus/constants";
import { InvalidPayloadError } from "@directus/errors";
import { defineEndpoint } from "@directus/extensions-sdk";
import { Accountability } from "@directus/types";
import { verifySignature } from "@joyid/core";
import { message } from "@unisat/wallet-sdk";
import { NetworkType } from "@unisat/wallet-sdk/lib/network";
import type { CookieOptions } from "express";
import Joi from "joi";
import jwt from "jsonwebtoken";
import ms from "ms";
import { nanoid } from "nanoid";

const getAccountability = (req: any) => {
  return req.accountability as Accountability;
};

const verifySchema = Joi.object({
  chain: Joi.valid("BTC", "ETH", "CKB").required(),
  address: Joi.string().required(),
  message: Joi.string().required(),
  signature: Joi.string().required(),
  challenge: Joi.when("chain", { is: "CKB", then: Joi.required() }),
  alg: Joi.when("chain", { is: "CKB", then: Joi.required() }),
  pubkey: Joi.when("chain", { is: "CKB", then: Joi.required() }),
  keyType: Joi.when("chain", { is: "CKB", then: Joi.required() }),
});

const verifyBTCSignature = (
  address: string,
  msg: string,
  signature: string,
  networkType: NetworkType
) => {
  try {
    const isVerified = message.verifyMessageOfBIP322Simple(
      address,
      msg,
      signature,
      networkType
    );
    return !!isVerified;
  } catch (error) {
    console.log(error);
    return false;
  }
};

export default {
  id: "web3login",
  handler: defineEndpoint(async (router, context) => {
    const { database, services, getSchema, env, logger } = context;
    const { UsersService, ActivityService } = services;
    const schema = await getSchema();
    const usersService = new UsersService({ schema });
    const activityService = new ActivityService({ schema });

    router.post("/verify", async (_req, res, next) => {
      try {
        const { error, value } = verifySchema.validate(_req.body);
        if (error)
          return next(new InvalidPayloadError({ reason: error.message }));

        const {
          address,
          chain,
          message,
          signature,
          challenge,
          alg,
          pubkey,
          keyType,
        } = value;

        // verify signature
        let isVerified = false;
        switch (chain) {
          case "BTC":
            isVerified = verifyBTCSignature(
              address,
              message,
              signature,
              env["TESTNET"] ? NetworkType.TESTNET : NetworkType.MAINNET
            );
            break;
          case "CKB":
            isVerified = await verifySignature({
              signature,
              message,
              challenge,
              alg,
              pubkey,
              keyType,
            });
            // TODO verify the relationship between `address` and `pubkey`
            break;
          case "ETH":
            break;
          default:
            break;
        }
        if (!isVerified) {
          return next(new InvalidPayloadError({ reason: "invalid signature" }));
        }

        // get or create User when signature validted.
        let user = await usersService.readSingleton({
          filter: { external_identifier: { _eq: address.toLocaleLowerCase() } },
        });

        if (!user.id) {
          const userId = await usersService.createOne({
            status: "active",
            external_identifier: address.toLocaleLowerCase(),
            role: env["AUTH_WEB3_DEFAULT_ROLE_ID"],
          });
          user = await usersService.readOne(userId);
        }

        if (user && user.status !== "active") {
          return res.status(400).json({ message: "User is inactive." });
        }
        // generate jwt token
        const tokenPayload = {
          id: user.id,
          role: user.role,
          app_access: false,
          admin_access: false,
        };
        const accessToken = jwt.sign(tokenPayload, env["SECRET"] as string, {
          expiresIn: env["ACCESS_TOKEN_TTL"],
          issuer: "directus",
        });
        const refreshToken = nanoid(64);
        const refreshTokenExpiration = new Date(
          Date.now() + ms(env["REFRESH_TOKEN_TTL"])
        );

        const accountability = getAccountability(_req);
        await database("directus_sessions").insert({
          token: refreshToken,
          user: user.id,
          expires: refreshTokenExpiration,
          ip: accountability?.ip,
          user_agent: accountability?.userAgent,
          origin: accountability?.origin,
        });

        await database("directus_sessions")
          .delete()
          .where("expires", "<", new Date());

        if (accountability) {
          await activityService.createOne({
            action: Action.LOGIN,
            user: user.id,
            ip: accountability.ip,
            user_agent: accountability.userAgent,
            origin: accountability.origin,
            collection: "directus_users",
            item: user.id,
          });
        }
        await database("directus_users")
          .update({ last_access: new Date() })
          .where({ id: user.id });

        const payload = {
          data: {
            access_token: accessToken,
            expires: ms(env["ACCESS_TOKEN_TTL"]),
          },
        } as Record<string, Record<string, any>>;
        const mode = _req.body.mode || "json";

        if (mode === "json") {
          payload["data"]!["refresh_token"] = refreshToken;
        }
        const COOKIE_OPTIONS: CookieOptions = {
          httpOnly: true,
          domain: env["REFRESH_TOKEN_COOKIE_DOMAIN"],
          maxAge: ms(env["REFRESH_TOKEN_TTL"]) as unknown as number,
          secure: env["REFRESH_TOKEN_COOKIE_SECURE"] ?? false,
          sameSite:
            (env["REFRESH_TOKEN_COOKIE_SAME_SITE"] as
              | "lax"
              | "strict"
              | "none") || "strict",
        };

        if (mode === "cookie") {
          res.cookie(
            env["REFRESH_TOKEN_COOKIE_NAME"],
            refreshToken,
            COOKIE_OPTIONS
          );
        }
        return res.status(200).json(payload);
      } catch (error) {
        logger.error(error);
        return res.status(500).json({ message: error });
      }
    });
  }),
};

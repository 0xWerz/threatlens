import { listPolicyPacks } from "../src/packs";

export const config = {
  runtime: "edge",
};

export default function handler(): Response {
  return new Response(
    JSON.stringify(
      {
        packs: listPolicyPacks(),
      },
      null,
      2,
    ),
    {
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "public, max-age=60",
      },
    },
  );
}

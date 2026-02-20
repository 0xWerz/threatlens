import { NextResponse } from "next/server";
import { listPolicyPacks } from "@/lib/packs";

export const runtime = "nodejs";

export async function GET(): Promise<NextResponse> {
  return NextResponse.json(
    {
      packs: listPolicyPacks(),
    },
    {
      headers: {
        "cache-control": "public, max-age=60",
      },
    },
  );
}

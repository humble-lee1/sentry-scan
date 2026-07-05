import { NextResponse } from 'next/server';
import { getSupabaseServerClient } from '@/lib/supabase-server';

export const revalidate = 60; // cache this for 60 seconds so every homepage
// load doesn't hit the database — still feels "live" since it refreshes every minute.

export async function GET() {
  try {
    const supabase = getSupabaseServerClient();
    const { count, error } = await supabase
      .from('scan_history')
      .select('*', { count: 'exact', head: true });

    if (error) throw error;

    return NextResponse.json({ count: count ?? 0 });
  } catch {
    // Non-fatal: if the DB is unavailable, just return 0 rather than
    // breaking the homepage entirely.
    return NextResponse.json({ count: 0 });
  }
}

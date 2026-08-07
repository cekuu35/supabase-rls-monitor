"use client"
import { createClient } from "@supabase/supabase-js"
const admin = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!)
export default function BuyCredits() { return null }

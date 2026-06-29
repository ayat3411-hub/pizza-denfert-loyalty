import AsyncStorage from "@react-native-async-storage/async-storage";
import { Platform } from "react-native";

// Choose the correct backend per environment:
//  - Production browsers on the Hetzner-served domains hit `https://api.pizzadenfert.fr`
//  - Everywhere else (Emergent dev preview, native dev/release) uses `EXPO_PUBLIC_BACKEND_URL`
const ENV_BASE = process.env.EXPO_PUBLIC_BACKEND_URL || "";
let BASE = ENV_BASE;
if (Platform.OS === "web" && typeof window !== "undefined" && window.location?.hostname) {
  const host = window.location.hostname;
  if (host === "pizzadenfert.fr" || host === "www.pizzadenfert.fr" || host === "admin.pizzadenfert.fr") {
    BASE = "https://api.pizzadenfert.fr";
  }
}

let _token: string | null = null;
export async function loadToken() {
  if (_token) return _token;
  _token = await AsyncStorage.getItem("@auth_token");
  return _token;
}
export async function setToken(t: string | null) {
  _token = t;
  if (t) await AsyncStorage.setItem("@auth_token", t);
  else await AsyncStorage.removeItem("@auth_token");
}

async function req(path: string, opts: RequestInit = {}) {
  const headers: any = { "Content-Type": "application/json", ...(opts.headers || {}) };
  const tok = await loadToken();
  if (tok) headers["Authorization"] = `Bearer ${tok}`;
  const r = await fetch(`${BASE}/api${path}`, { ...opts, headers });
  if (!r.ok) {
    const txt = await r.text();
    throw new Error(`${r.status}: ${txt}`);
  }
  return r.json();
}

export const api = {
  otpRequest: (phone: string, name?: string) =>
    req("/auth/otp/request", { method: "POST", body: JSON.stringify({ phone, name }) }),
  otpVerify: (phone: string, code: string, name?: string) =>
    req("/auth/otp/verify", { method: "POST", body: JSON.stringify({ phone, code, name }) }),
  register: (email: string, password: string, name: string) =>
    req("/auth/register", { method: "POST", body: JSON.stringify({ email, password, name }) }),
  login: (email: string, password: string) =>
    req("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  googleSession: (session_id: string) =>
    req("/auth/google/session", { method: "POST", body: JSON.stringify({ session_id }) }),
  me: () => req("/auth/me"),
  logout: () => req("/auth/logout", { method: "POST" }),
  menu: () => req("/menu"),
  menuVersion: () => req("/menu/version"),
  adminListMenu: () => req("/admin/menu"),
  adminCreateMenuItem: (data: any) => req("/admin/menu", { method: "POST", body: JSON.stringify(data) }),
  adminUpdateMenuItem: (id: string, patch: any) =>
    req(`/admin/menu/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(patch) }),
  adminDeleteMenuItem: (id: string) =>
    req(`/admin/menu/${encodeURIComponent(id)}`, { method: "DELETE" }),
  createReservation: (data: any) => req("/reservations", { method: "POST", body: JSON.stringify(data) }),
  createGuestReservation: (data: any) => req("/reservations/guest", { method: "POST", body: JSON.stringify(data) }),
  reservationAvailability: (date: string, time: string) =>
    req(`/reservations/availability?date=${encodeURIComponent(date)}&time=${encodeURIComponent(time)}`),
  myReservations: () => req("/reservations/me"),
  loyalty: () => req("/loyalty/me"),
  redeem: (reward: string) => req("/loyalty/redeem", { method: "POST", body: JSON.stringify({ reward }) }),
  adminScan: (qr_data: string) => req("/admin/scan", { method: "POST", body: JSON.stringify({ qr_data }) }),
  adminSearch: (query: string) => req("/admin/search", { method: "POST", body: JSON.stringify({ query }) }),
  adminAddPizza: (user_id: string, qr_token: string, pizza_count: number = 1, pizza_id?: string | null) =>
    req("/admin/customer/add-pizza", { method: "POST", body: JSON.stringify({ user_id, qr_token, pizza_count, pizza_id: pizza_id || null }) }),
  adminRedeem: (user_id: string, qr_token: string, reward: string) =>
    req("/admin/customer/redeem", { method: "POST", body: JSON.stringify({ user_id, qr_token, reward }) }),
  adminDashboard: (period: "today" | "week" | "month" | "all" = "all") =>
    req(`/admin/dashboard?period=${period}`),
  adminCreateStaff: (phone: string, name: string, role: string) =>
    req("/admin/staff/create", { method: "POST", body: JSON.stringify({ phone, name, role }) }),
  adminListStaff: () => req("/admin/staff"),
  adminUpdateRole: (user_id: string, role: string) =>
    req(`/admin/staff/${encodeURIComponent(user_id)}/role`, { method: "PATCH", body: JSON.stringify({ role }) }),
  adminToggleDisabled: (user_id: string, disabled: boolean) =>
    req(`/admin/staff/${encodeURIComponent(user_id)}/disable`, { method: "PATCH", body: JSON.stringify({ disabled }) }),
  adminDeleteStaff: (user_id: string) =>
    req(`/admin/staff/${encodeURIComponent(user_id)}`, { method: "DELETE" }),
  adminGetCapacity: () => req("/admin/settings/capacity"),
  adminUpdateCapacity: (indoor: number, terrace: number, extras?: { tables_indoor?: number; tables_terrace?: number; seats_per_table?: number }) =>
    req("/admin/settings/capacity", { method: "PUT", body: JSON.stringify({ indoor, terrace, ...(extras || {}) }) }),
  adminListReservations: (params: { period?: string; from_date?: string; to_date?: string; status?: string; q?: string; zone?: string; limit?: number } = {}) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== "") qs.set(k, String(v)); });
    const s = qs.toString();
    return req(`/admin/reservations${s ? `?${s}` : ""}`);
  },
  adminReservationsDay: (date: string) =>
    req(`/admin/reservations/day?date=${encodeURIComponent(date)}`),
  adminUpdateReservation: (rid: string, patch: any) =>
    req(`/admin/reservations/${encodeURIComponent(rid)}`, { method: "PATCH", body: JSON.stringify(patch) }),
  adminCreateReservation: (data: any) =>
    req(`/admin/reservations`, { method: "POST", body: JSON.stringify(data) }),
  pushPublicKey: () => req("/push/web/public-key"),
  pushSubscribe: (sub: { endpoint: string; keys: any }) =>
    req("/push/web/subscribe", { method: "POST", body: JSON.stringify(sub) }),
  pushUnsubscribe: (sub: { endpoint: string; keys: any }) =>
    req("/push/web/unsubscribe", { method: "POST", body: JSON.stringify(sub) }),
  pushStatus: () => req("/push/web/status"),
  pushTest: () => req("/push/web/test", { method: "POST" }),
  // Kiosk / Advertising Management
  publicAdSlides: () => req("/ads/slides"),
  adminListAdSlides: () => req("/admin/ads/slides"),
  adminCreateAdSlide: (data: { section: "loyalty"|"experience"|"ingredients"; title: string; subtitle?: string; image_url?: string; duration_ms?: number; active?: boolean; order?: number }) =>
    req("/admin/ads/slides", { method: "POST", body: JSON.stringify(data) }),
  adminUpdateAdSlide: (id: string, patch: any) =>
    req(`/admin/ads/slides/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(patch) }),
  adminDeleteAdSlide: (id: string) =>
    req(`/admin/ads/slides/${encodeURIComponent(id)}`, { method: "DELETE" }),
  adminReorderAdSlides: (ids: string[]) =>
    req(`/admin/ads/reorder`, { method: "PUT", body: JSON.stringify({ ids }) }),
  adminGetKioskSettings: () => req("/admin/ads/settings"),
  adminUpdateKioskSettings: (patch: { idle_seconds?: number; loop?: boolean; default_duration_ms?: number; show_section_titles?: boolean }) =>
    req("/admin/ads/settings", { method: "PUT", body: JSON.stringify(patch) }),
};

export { BASE };

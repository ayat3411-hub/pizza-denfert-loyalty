import React, { useEffect, useMemo, useState, useCallback, useRef } from "react";
import { View, Text, StyleSheet, ScrollView, ActivityIndicator, FlatList, Pressable, RefreshControl, AppState } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { useFocusEffect } from "expo-router";
import { Image } from "expo-image";
import { useI18n } from "@/src/i18n";
import { api } from "@/src/api";
import { theme } from "@/src/theme";

// Unified shape used by the renderer (FastAPI / MongoDB menu rows).
type Row = {
  id: string;
  name: string;
  desc?: string | null;
  ingredients?: string | null;
  image?: string;
  // Either a single `price` (number) OR a `prices` map (e.g. { "26": 10.9, "31": 13.9 }).
  price?: number | null;
  prices?: Record<string, number> | null;
  category_slug: string; // slug used by chips
};

const LEGACY_FALLBACK_CATS = [
  { id: "pizzas", slug: "pizzas", name: "Pizzas", sort_order: 1 },
  { id: "focaccias", slug: "focaccias", name: "Focaccias", sort_order: 2 },
  { id: "gratins", slug: "gratins", name: "Gratins", sort_order: 3 },
  { id: "salades", slug: "salades", name: "Salades", sort_order: 4 },
  { id: "desserts", slug: "desserts", name: "Desserts", sort_order: 5 },
  { id: "boissons", slug: "boissons", name: "Boissons", sort_order: 6 },
  { id: "vins", slug: "vins", name: "Vins", sort_order: 7 },
];

export default function MenuScreen() {
  const { t, lang } = useI18n();
  const [rows, setRows] = useState<Row[]>([]);
  const [cats, setCats] = useState<{ id: string; slug: string; name: string; sort_order: number }[]>(LEGACY_FALLBACK_CATS);
  const [cat, setCat] = useState<string>("pizzas");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const revRef = useRef<number | null>(null);

  const mapItems = useCallback((items: any[]): Row[] => (items || []).map((m: any) => ({
    id: m.id,
    name: m.name,
    desc: lang === "fr" ? m.desc_fr : m.desc_en,
    ingredients: lang === "fr" ? m.ingredients_fr : m.ingredients_en,
    image: m.image,
    price: typeof m.price === "number" ? m.price : null,
    prices: m.prices || null,
    category_slug: m.category,
  })), [lang]);

  // Fetch the menu. `spinner` shows the full-screen loader (initial load only);
  // background refreshes update silently so the screen never flickers.
  const fetchMenu = useCallback(async (spinner = false) => {
    if (spinner) setLoading(true);
    try {
      const items = await api.menu();
      setCats(LEGACY_FALLBACK_CATS);
      setRows(mapItems(items));
      try { const v = await api.menuVersion(); if (v) revRef.current = v.rev; } catch {}
    } catch (e) {
      console.error("Menu load failed", e);
      if (spinner) setRows([]);
    } finally {
      if (spinner) setLoading(false);
    }
  }, [mapItems]);

  // Refetch only if the CMS revision changed (cheap /menu/version check).
  const refreshIfChanged = useCallback(async () => {
    try {
      const v = await api.menuVersion();
      if (v && v.rev !== revRef.current) await fetchMenu(false);
    } catch {}
  }, [fetchMenu]);

  // Initial load (+ re-localise when language changes).
  useEffect(() => { fetchMenu(true); }, [fetchMenu]);

  // Auto-refresh #1: whenever the Menu screen regains focus.
  useFocusEffect(useCallback(() => { refreshIfChanged(); }, [refreshIfChanged]));

  // Auto-refresh #2: light polling (every 20s) while the screen is focused.
  useFocusEffect(useCallback(() => {
    const id = setInterval(refreshIfChanged, 20000);
    return () => clearInterval(id);
  }, [refreshIfChanged]));

  // Auto-refresh #3: when the app returns to the foreground.
  useEffect(() => {
    const sub = AppState.addEventListener("change", (s) => { if (s === "active") refreshIfChanged(); });
    return () => sub.remove();
  }, [refreshIfChanged]);

  const filtered = useMemo(() => rows.filter((r) => r.category_slug === cat), [rows, cat]);

  // Localised category label fallback (i18n keys exist for the canonical 7 slugs).
  const labelFor = (c: { slug: string; name: string }) => {
    try { const k = `categories.${c.slug}` as any; const v = t(k); if (v && v !== k) return v; } catch {}
    return c.name;
  };

  return (
    <View testID="menu-screen" style={styles.container}>
      <SafeAreaView edges={["top"]} style={styles.header}>
        <Text style={styles.eyebrow}>— LA CARTE</Text>
        <Text style={styles.title}>{t("menu")}</Text>
        <ScrollView
          horizontal
          showsHorizontalScrollIndicator={false}
          contentContainerStyle={styles.chipsRow}
          style={styles.chipsScroll}
        >
          {cats.map((c) => (
            <Pressable key={c.slug} testID={`cat-chip-${c.slug}`} onPress={() => setCat(c.slug)} style={[styles.chip, cat === c.slug && styles.chipActive]}>
              <Text style={[styles.chipTxt, cat === c.slug && styles.chipTxtActive]}>{labelFor(c)}</Text>
            </Pressable>
          ))}
        </ScrollView>
      </SafeAreaView>

      {loading ? (
        <View style={{ flex: 1, alignItems: "center", justifyContent: "center" }}>
          <ActivityIndicator color={theme.color.brand} />
        </View>
      ) : filtered.length === 0 ? (
        <View style={{ flex: 1, alignItems: "center", justifyContent: "center", padding: theme.space.xl }}>
          <Text style={{ color: theme.color.muted, fontSize: 13, textAlign: "center", fontStyle: "italic" }}>
            {lang === "fr" ? "Aucun plat dans cette catégorie pour le moment." : "No dishes in this category yet."}
          </Text>
        </View>
      ) : (
        <FlatList
          data={filtered}
          keyExtractor={(i) => i.id}
          contentContainerStyle={{ padding: theme.space.lg, paddingBottom: 140, paddingTop: theme.space.md }}
          refreshControl={<RefreshControl refreshing={refreshing} tintColor={theme.color.brand} onRefresh={async () => { setRefreshing(true); await fetchMenu(false); setRefreshing(false); }} />}
          renderItem={({ item }) => {
            const sizeKeys = item.prices ? Object.keys(item.prices).filter((k) => k !== "default") : [];
            const showSizes = sizeKeys.length >= 2;
            return (
              <View testID={`menu-item-${item.id}`} style={styles.card}>
                {!!item.image && (
                  <View style={styles.imgWrap}>
                    <Image source={item.image} style={styles.cardImg} contentFit="cover" />
                  </View>
                )}
                <View style={styles.cardBody}>
                  <View style={styles.cardHead}>
                    <Text style={styles.itemName}>{item.name}</Text>
                    {!showSizes && typeof item.price === "number" && item.price > 0 && (
                      <Text style={styles.price}>{item.price.toFixed(2)} €</Text>
                    )}
                  </View>
                  {!!item.desc && <Text style={styles.itemDesc}>{item.desc}</Text>}
                  {!!item.ingredients && (
                    <>
                      <Text style={styles.ingredientsLbl}>{lang === "fr" ? "INGRÉDIENTS" : "INGREDIENTS"}</Text>
                      <Text style={styles.ingredients}>{item.ingredients}</Text>
                    </>
                  )}
                  {showSizes && (
                    <View style={styles.sizesRow}>
                      {sizeKeys.sort().map((k) => (
                        <View key={k} style={styles.sizeBox}>
                          <Text style={styles.sizeLbl}>{/^\d+$/.test(k) ? `${k} cm` : k.toUpperCase()}</Text>
                          <Text style={styles.sizePrice}>{Number(item.prices![k]).toFixed(2)} €</Text>
                        </View>
                      ))}
                    </View>
                  )}
                </View>
              </View>
            );
          }}
        />
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: theme.color.surface },
  header: { paddingHorizontal: theme.space.xl, paddingTop: theme.space.md, paddingBottom: theme.space.sm, borderBottomWidth: 0.5, borderBottomColor: theme.color.border, backgroundColor: theme.color.surface },
  eyebrow: { color: theme.color.brand, letterSpacing: 3, fontSize: 10, fontWeight: "700", marginBottom: 6 },
  title: { color: theme.color.onSurface, fontSize: 34, fontWeight: "300", letterSpacing: -1 },
  chipsScroll: { marginTop: theme.space.lg, marginHorizontal: -theme.space.xl },
  chipsRow: { paddingHorizontal: theme.space.xl, gap: 8, paddingVertical: 4 },
  chip: { height: 36, paddingHorizontal: 16, borderRadius: 999, borderWidth: 1, borderColor: theme.color.borderStrong, justifyContent: "center", flexShrink: 0 },
  chipActive: { borderColor: theme.color.brand, backgroundColor: "rgba(212,175,55,0.12)" },
  chipTxt: { color: theme.color.onSurfaceTertiary, fontSize: 12, fontWeight: "600", letterSpacing: 0.5 },
  chipTxtActive: { color: theme.color.brand },
  card: { backgroundColor: theme.color.surfaceSecondary, borderRadius: theme.radius.lg, overflow: "hidden", marginBottom: theme.space.lg, borderWidth: 1, borderColor: theme.color.border },
  imgWrap: { height: 200 },
  cardImg: { ...StyleSheet.absoluteFillObject as any },
  cardBody: { padding: theme.space.lg },
  cardHead: { flexDirection: "row", justifyContent: "space-between", alignItems: "flex-start", gap: 12 },
  itemName: { color: theme.color.onSurface, fontSize: 20, fontWeight: "500", flex: 1 },
  itemDesc: { color: theme.color.onSurfaceTertiary, fontSize: 13, lineHeight: 18, marginTop: 4, fontStyle: "italic" },
  ingredientsLbl: { color: theme.color.brand, fontSize: 9, letterSpacing: 2, fontWeight: "700", marginTop: 12 },
  ingredients: { color: theme.color.onSurfaceSecondary, fontSize: 13, lineHeight: 19, marginTop: 4 },
  price: { color: theme.color.brand, fontSize: 18, fontWeight: "600" },
  sizesRow: { flexDirection: "row", gap: 10, marginTop: theme.space.lg, flexWrap: "wrap" },
  sizeBox: { flex: 1, minWidth: 100, padding: 12, borderRadius: theme.radius.md, borderWidth: 1, borderColor: theme.color.brand, alignItems: "center" },
  sizeLbl: { color: theme.color.onSurfaceTertiary, fontSize: 11, letterSpacing: 2, fontWeight: "600" },
  sizePrice: { color: theme.color.brand, fontSize: 18, fontWeight: "600", marginTop: 4 },
});

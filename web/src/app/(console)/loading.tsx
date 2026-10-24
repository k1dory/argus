import { PageSkeleton } from "@/components/console/skeletons";

/** Скелет страницы консоли на время серверного рендера: шапка уже видна. */
export default function ConsoleLoading() {
  return <PageSkeleton />;
}

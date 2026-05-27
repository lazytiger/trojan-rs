export function addSelectedApp(selectedApps, packageName) {
  const app = String(packageName ?? "").trim();
  const apps = Array.isArray(selectedApps) ? selectedApps : [];
  if (app === "" || apps.includes(app)) {
    return [...apps];
  }
  return [...apps, app];
}

export function removeSelectedApp(selectedApps, packageName) {
  const app = String(packageName ?? "").trim();
  const apps = Array.isArray(selectedApps) ? selectedApps : [];
  return apps.filter((selectedApp) => selectedApp !== app);
}

export function filterAvailableApps(apps, selectedApps) {
  const selected = new Set(Array.isArray(selectedApps) ? selectedApps : []);
  return (Array.isArray(apps) ? apps : []).filter(
    (app) => !selected.has(app.value),
  );
}

export const GMS_PACKAGES = [
  "com.google.android.gms",
  "com.google.android.gsf",
  "com.android.vending",
];

export function normalizePackageNames(packageNames) {
  const seen = new Set();
  const normalized = [];
  for (const rawPackageName of Array.isArray(packageNames) ? packageNames : []) {
    const packageName = String(rawPackageName ?? "").trim();
    if (packageName !== "" && !seen.has(packageName)) {
      seen.add(packageName);
      normalized.push(packageName);
    }
  }
  return normalized;
}

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

export function toAppItems(apps) {
  return (Array.isArray(apps) ? apps : []).map((app) => ({
    label: app.label,
    packageName: app.package_name,
    title: `${app.label} (${app.package_name})`,
    value: app.package_name,
  }));
}

export function filterAvailableApps(apps, selectedApps) {
  const selected = new Set(Array.isArray(selectedApps) ? selectedApps : []);
  return (Array.isArray(apps) ? apps : []).filter(
    (app) => !selected.has(app.value),
  );
}

export function getDisplayedSelectedApps(
  selectedApps,
  runningAllowedApps,
  running,
) {
  return normalizePackageNames(running ? runningAllowedApps : selectedApps);
}

export function toSelectedAppItems(packageNames, apps) {
  const appMap = new Map(
    (Array.isArray(apps) ? apps : []).map((app) => [
      app.packageName ?? app.value,
      app,
    ]),
  );
  return normalizePackageNames(packageNames).map((packageName) => {
    const app = appMap.get(packageName);
    return {
      label: app?.label ?? packageName,
      packageName,
    };
  });
}

export function getInstalledGmsPackages(apps) {
  const installed = new Set(
    (Array.isArray(apps) ? apps : []).map((app) => app.value),
  );
  return GMS_PACKAGES.filter((packageName) => installed.has(packageName));
}

export function setGmsAppsSelected(selectedApps, apps, selected) {
  const current = Array.isArray(selectedApps) ? selectedApps : [];
  const gmsPackages = GMS_PACKAGES;

  if (!selected) {
    const gmsSet = new Set(gmsPackages);
    return current.filter((packageName) => !gmsSet.has(packageName));
  }

  return gmsPackages.reduce(
    (nextSelectedApps, packageName) =>
      addSelectedApp(nextSelectedApps, packageName),
    current,
  );
}

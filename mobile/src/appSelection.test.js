import test from "node:test";
import assert from "node:assert/strict";

import {
  addSelectedApp,
  filterAvailableApps,
  getDisplayedSelectedApps,
  getInstalledGmsPackages,
  removeSelectedApp,
  setGmsAppsSelected,
  toAppItems,
  toSelectedAppItems,
} from "./appSelection.js";

test("addSelectedApp appends a new app and ignores duplicates", () => {
  assert.deepEqual(
    addSelectedApp(["com.openai.chatgpt"], "com.google.android.gms"),
    ["com.openai.chatgpt", "com.google.android.gms"],
  );
  assert.deepEqual(
    addSelectedApp(["com.openai.chatgpt"], "com.openai.chatgpt"),
    ["com.openai.chatgpt"],
  );
});

test("removeSelectedApp removes only the requested package", () => {
  assert.deepEqual(
    removeSelectedApp(
      ["com.openai.chatgpt", "com.google.android.gms", "com.android.chrome"],
      "com.google.android.gms",
    ),
    ["com.openai.chatgpt", "com.android.chrome"],
  );
});

test("filterAvailableApps hides already selected apps", () => {
  const apps = [
    { title: "ChatGPT", value: "com.openai.chatgpt" },
    { title: "Google Play services", value: "com.google.android.gms" },
    { title: "Chrome", value: "com.android.chrome" },
  ];

  assert.deepEqual(
    filterAvailableApps(apps, ["com.openai.chatgpt", "com.android.chrome"]),
    [{ title: "Google Play services", value: "com.google.android.gms" }],
  );
});

test("toAppItems maps installed app payloads for selection controls", () => {
  assert.deepEqual(
    toAppItems([
      { label: "Chrome", package_name: "com.android.chrome" },
      { label: "Play Store", package_name: "com.android.vending" },
    ]),
    [
      {
        label: "Chrome",
        packageName: "com.android.chrome",
        title: "Chrome (com.android.chrome)",
        value: "com.android.chrome",
      },
      {
        label: "Play Store",
        packageName: "com.android.vending",
        title: "Play Store (com.android.vending)",
        value: "com.android.vending",
      },
    ],
  );
});

test("getInstalledGmsPackages returns installed GMS packages in bundle order", () => {
  const apps = [
    { title: "Chrome", value: "com.android.chrome" },
    { title: "Google Play Store", value: "com.android.vending" },
    { title: "Google Services Framework", value: "com.google.android.gsf" },
    { title: "Google Play services", value: "com.google.android.gms" },
  ];

  assert.deepEqual(getInstalledGmsPackages(apps), [
    "com.google.android.gms",
    "com.google.android.gsf",
    "com.android.vending",
  ]);
});

test("setGmsAppsSelected adds all fixed GMS package names without relying on app list enumeration", () => {
  const apps = [
    { title: "GSF Proxy", value: "com.google.android.gsf" },
  ];

  assert.deepEqual(setGmsAppsSelected(["com.openai.chatgpt"], apps, true), [
    "com.openai.chatgpt",
    "com.google.android.gms",
    "com.google.android.gsf",
    "com.android.vending",
  ]);
});

test("setGmsAppsSelected removes only GMS packages", () => {
  assert.deepEqual(
    setGmsAppsSelected(
      [
        "com.openai.chatgpt",
        "com.google.android.gms",
        "com.google.android.gsf",
        "com.android.vending",
      ],
      [],
      false,
    ),
    ["com.openai.chatgpt"],
  );
});

test("getDisplayedSelectedApps returns configured apps while VPN is stopped", () => {
  assert.deepEqual(
    getDisplayedSelectedApps(
      ["com.openai.chatgpt", "com.google.android.gms"],
      ["com.openai.chatgpt"],
      false,
    ),
    ["com.openai.chatgpt", "com.google.android.gms"],
  );
});

test("getDisplayedSelectedApps returns actual allowed apps while VPN is running", () => {
  assert.deepEqual(
    getDisplayedSelectedApps(
      ["com.openai.chatgpt", "com.google.android.gms"],
      ["com.openai.chatgpt"],
      true,
    ),
    ["com.openai.chatgpt"],
  );
});

test("toSelectedAppItems maps package names to installed labels with package fallback", () => {
  const apps = [
    {
      label: "ChatGPT",
      packageName: "com.openai.chatgpt",
      value: "com.openai.chatgpt",
    },
  ];

  assert.deepEqual(
    toSelectedAppItems(["com.openai.chatgpt", "com.missing.app"], apps),
    [
      {
        label: "ChatGPT",
        packageName: "com.openai.chatgpt",
      },
      {
        label: "com.missing.app",
        packageName: "com.missing.app",
      },
    ],
  );
});

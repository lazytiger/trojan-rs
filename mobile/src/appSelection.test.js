import test from "node:test";
import assert from "node:assert/strict";

import {
  addSelectedApp,
  filterAvailableApps,
  getInstalledGmsPackages,
  removeSelectedApp,
  setGmsAppsSelected,
  toAppItems,
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

test("setGmsAppsSelected adds installed GMS packages without duplicates", () => {
  const apps = [
    { title: "Google Play Store", value: "com.android.vending" },
    { title: "Google Play services", value: "com.google.android.gms" },
  ];

  assert.deepEqual(setGmsAppsSelected(["com.openai.chatgpt"], apps, true), [
    "com.openai.chatgpt",
    "com.google.android.gms",
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

import test from "node:test";
import assert from "node:assert/strict";

import {
  addSelectedApp,
  filterAvailableApps,
  removeSelectedApp,
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

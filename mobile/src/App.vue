<script>
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

import {
  addSelectedApp,
  filterAvailableApps,
  getInstalledGmsPackages,
  removeSelectedApp,
  setGmsAppsSelected,
} from "./appSelection.js";

const VPN_PERMISSION = "android.permission.BIND_VPN_SERVICE";
const defaultConfig = () => ({
  hostname: "",
  password: "",
  pool_size: 20,
  mtu: 1500,
  port: 443,
  trusted_dns: "8.8.8.8",
  dns_cache_time: 600,
  log_level: "Error",
  speed_update_ms: 2000,
  selected_apps: [],
});

export default {
  data() {
    return {
      show: false,
      config: defaultConfig(),
      apps: [],
      appToAdd: null,
      appSearch: "",
      configReady: false,
      label: "开始",
      running: false,
      homeVisible: true,
      ladderVisible: false,
      showResult: false,
      domains: [],
      query: "",
      network_lost: false,
      process_exit: true,
    };
  },
  watch: {
    "config.selected_apps": {
      deep: true,
      async handler() {
        if (this.configReady) {
          await this.saveConfig();
        }
      },
    },
  },
  computed: {
    availableApps() {
      return filterAvailableApps(this.apps, this.config.selected_apps);
    },
    installedGmsPackages() {
      return getInstalledGmsPackages(this.apps);
    },
    gmsSelected: {
      get() {
        return (
          this.installedGmsPackages.length > 0 &&
          this.installedGmsPackages.every((packageName) =>
            this.config.selected_apps.includes(packageName),
          )
        );
      },
      set(selected) {
        this.config.selected_apps = setGmsAppsSelected(
          this.config.selected_apps,
          this.apps,
          selected,
        );
      },
    },
    gmsIndeterminate() {
      const selectedCount = this.installedGmsPackages.filter((packageName) =>
        this.config.selected_apps.includes(packageName),
      ).length;
      return (
        selectedCount > 0 && selectedCount < this.installedGmsPackages.length
      );
    },
    selectedAppItems() {
      const appMap = new Map(this.apps.map((app) => [app.value, app]));
      return this.config.selected_apps.map((packageName) => {
        const app = appMap.get(packageName);
        return {
          label: app?.label ?? packageName,
          packageName,
        };
      });
    },
  },
  methods: {
    async saveConfig() {
      await invoke("save_data", {
        key: "config",
        value: JSON.stringify(this.config),
      });
    },
    async start() {
      await this.saveConfig();
      if (!this.running) {
        await invoke("start_vpn", { options: this.config });
        this.label = "启动中";
      }
    },
    async stop() {
      if (this.running) {
        await invoke("stop_vpn", {});
      }
    },
    async init_listener() {
      await listen("on_status_changed", async (event) => {
        if (event.payload === "VpnStart") {
          this.running = true;
          this.process_exit = false;
          this.label = "停止";
        } else if (event.payload === "ProcessExit") {
          if (this.network_lost) {
            this.process_exit = true;
          } else if (this.running) {
            await invoke("start_process", {});
            this.label = "重启中";
          }
        } else if (event.payload === "VpnStop") {
          this.process_exit = true;
          this.running = false;
          this.label = "开始";
        } else if (event.payload === "NetworkAvailable") {
          if (this.process_exit && this.running) {
            await invoke("start_process", {});
            this.label = "网络重启中";
          }
          this.network_lost = false;
        } else if (event.payload === "NetworkLost") {
          this.label = "网络连接断开";
          this.network_lost = true;
        }
      });
      await listen("update_speed", async (event) => {
        if (this.running) {
          this.label = "停止";
          await invoke("update_notification", { content: event.payload });
        }
      });
      await listen("open_config", async () => {
        this.showHome();
      });
    },
    do_action() {
      if (this.label !== "开始" && this.label !== "停止") {
        return;
      }
      if (!this.running) {
        this.start();
      } else {
        this.stop();
      }
    },
    config_ok() {
      return (
        this.config.hostname !== "" &&
        this.config.password !== "" &&
        this.config.selected_apps.length > 0 &&
        (this.label === "开始" || this.label === "停止")
      );
    },
    showHome() {
      this.homeVisible = true;
      this.ladderVisible = false;
    },
    showLadder() {
      this.ladderVisible = true;
      this.homeVisible = false;
    },
    appFilter(value, query, item) {
      const needle = query.toString().toLowerCase();
      const raw = item?.raw ?? {};
      return `${raw.title ?? value ?? ""} ${raw.value ?? ""}`
        .toLowerCase()
        .includes(needle);
    },
    addApp(packageName) {
      if (this.running) {
        return;
      }
      this.config.selected_apps = addSelectedApp(
        this.config.selected_apps,
        packageName,
      );
      this.appToAdd = null;
      this.appSearch = "";
    },
    removeApp(packageName) {
      if (this.running) {
        return;
      }
      this.config.selected_apps = removeSelectedApp(
        this.config.selected_apps,
        packageName,
      );
    },
    async handleDomain(item) {
      if (item.id === -1) {
        await invoke("add_domain", { key: this.query });
      } else {
        for (let i = 0; i < this.domains.length; i++) {
          let domain = this.domains[i];
          if (domain.value === item.id) {
            await invoke("remove_domain", { key: domain.title });
            break;
          }
        }
      }
      await this.doQuery();
    },
    async doQuery() {
      let domains = await invoke("search_domain", { key: this.query });
      this.domains = [];
      for (let i = 0; i < domains.length; i++) {
        let domain = domains[i];
        this.domains.push({ title: domain, value: i });
      }
      if (this.domains.length === 0) {
        this.domains.push({ title: "未找到该域名，点击添加", value: -1 });
      }
      this.showResult = this.domains.length > 0;
    },
  },
  async mounted() {
    let data = await invoke("load_data", { key: "config" });
    if (data !== "") {
      try {
        const loaded = JSON.parse(data.toString());
        if (loaded.selected_app && !loaded.selected_apps) {
          loaded.selected_apps = [loaded.selected_app];
          delete loaded.selected_app;
        }
        if (typeof loaded.selected_apps === "string") {
          loaded.selected_apps = loaded.selected_apps
            ? [loaded.selected_apps]
            : [];
        }
        this.config = { ...defaultConfig(), ...loaded };
      } catch (err) {
        console.error("Failed to parse config, using default config", err);
        this.config = defaultConfig();
      }
      this.config.speed_update_ms = 2000;
    }
    this.apps = (await invoke("list_installed_apps", {})).map((app) => ({
      label: app.label,
      packageName: app.package_name,
      title: `${app.label} (${app.package_name})`,
      value: app.package_name,
    }));
    this.configReady = true;
    await invoke("init_window", { logLevel: this.config.log_level });
    await this.init_listener();
  },
};
</script>

<template>
  <v-app>
    <v-main class="bg-grey-lighten-4">
      <v-toolbar color="blue" dark="true">
        <v-toolbar-title>AppRouter</v-toolbar-title>
        <v-spacer></v-spacer>
        <v-btn icon @click="showHome">
          <v-icon>mdi-home-edit-outline</v-icon>
        </v-btn>
        <v-btn icon @click="showLadder">
          <v-icon>mdi-ladder</v-icon>
        </v-btn>
      </v-toolbar>
      <div v-if="homeVisible">
        <v-container class="mx-auto" style="max-width: 480px">
          <v-text-field
            v-model="config.hostname"
            :readonly="running"
            label="服务器域名"
            variant="outlined"
          ></v-text-field>
          <v-text-field
            v-model="config.password"
            :append-icon="show ? 'mdi-eye' : 'mdi-eye-off'"
            :readonly="running"
            :type="show ? 'text' : 'password'"
            label="服务器密码"
            variant="outlined"
            @click:append="show = !show"
          ></v-text-field>
          <v-text-field
            v-model="config.trusted_dns"
            :readonly="running"
            label="可信DNS"
            variant="outlined"
          ></v-text-field>
          <v-checkbox
            v-model="gmsSelected"
            :disabled="running || installedGmsPackages.length === 0"
            :indeterminate="gmsIndeterminate"
            density="compact"
            hide-details
            label="GMS三件套"
          ></v-checkbox>
          <div class="selected-apps">
            <div class="selected-apps__title">Selected app</div>
            <v-list
              v-if="selectedAppItems.length > 0"
              class="selected-apps__list"
              density="compact"
            >
              <v-list-item
                v-for="app in selectedAppItems"
                :key="app.packageName"
                :subtitle="app.packageName"
                :title="app.label"
              >
                <template v-slot:append>
                  <v-btn
                    :disabled="running"
                    icon="mdi-close"
                    size="small"
                    variant="text"
                    @click="removeApp(app.packageName)"
                  ></v-btn>
                </template>
              </v-list-item>
            </v-list>
          </div>
          <v-autocomplete
            v-model="appToAdd"
            v-model:search="appSearch"
            :custom-filter="appFilter"
            :items="availableApps"
            :readonly="running"
            clearable
            item-title="title"
            item-value="value"
            label="添加VPN应用"
            variant="outlined"
            @update:model-value="addApp"
          ></v-autocomplete>
          <v-combobox
            v-model="config.log_level"
            :items="['Trace', 'Debug', 'Info', 'Warn', 'Error', 'Off']"
            :readonly="running"
            label="日志级别"
            variant="solo"
          ></v-combobox>
          <v-slider
            v-model="config.pool_size"
            :readonly="running"
            label="连接池大小"
            max="20"
            min="0"
            step="1"
          >
            <template v-slot:append>
              <v-text-field
                v-model="config.pool_size"
                :readonly="running"
                density="compact"
                hide-details
                single-line
                style="width: 70px"
                type="number"
              ></v-text-field>
            </template>
          </v-slider>
          <v-btn
            :disabled="!config_ok()"
            block=""
            color="blue"
            size="x-large"
            @click="do_action"
            >{{ label }}</v-btn
          >
        </v-container>
      </div>
      <div v-if="ladderVisible">
        <v-container class="mx-auto" style="max-width: 480px">
          <v-row>
            <v-col>
              <v-text-field
                v-model="query"
                label="域名关键字"
                variant="outlined"
              ></v-text-field>
            </v-col>
            <v-col cols="2">
              <v-btn icon @click="doQuery">
                <v-icon>mdi-tab-search</v-icon>
              </v-btn>
            </v-col>
          </v-row>
          <div v-if="showResult">
            <v-list
              :items="domains"
              class="my-list"
              @click:select="handleDomain"
            >
            </v-list>
          </div>
        </v-container>
      </div>
    </v-main>
  </v-app>
</template>

<style>
.my-list {
  background-color: #f5f5f5;
  padding: 10px;
  border: 1px solid #ccc;
}

.selected-apps {
  margin-bottom: 22px;
}

.selected-apps__title {
  color: rgba(0, 0, 0, 0.6);
  font-size: 12px;
  line-height: 18px;
  margin: -10px 0 4px 12px;
}

.selected-apps__list {
  background: transparent;
  border: 1px solid #d8d8d8;
  border-radius: 4px;
  padding: 0;
}

.selected-apps__list .v-list-item-title {
  font-size: 14px;
  line-height: 20px;
  white-space: normal;
}

.selected-apps__list .v-list-item-subtitle {
  font-size: 12px;
  line-height: 18px;
  white-space: normal;
}
</style>

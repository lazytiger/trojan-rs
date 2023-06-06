<script>
import {invoke} from "@tauri-apps/api";
import {appWindow} from "@tauri-apps/plugin-window";

async function update_speed() {
  await invoke("update_speed", {});
}

const VPN_PERMISSION = "android.permission.BIND_VPN_SERVICE";

export default {
  data() {
    return {
      show: false,
      config: {
        hostname: "",
        password: "",
        pool_size: 20,
        mtu: 1500,
        port: 443,
      },
      label: "开始",
      running: false,
    }
  },
  methods: {
    async start() {
      await invoke("save_data", {key:"config", value:JSON.stringify(this.config)});
      if (!this.running) {
        await invoke("start_vpn", {option: this.config});
      }
    },
    stop() {
      if (this.running) {
        invoke("stop_vpn", {});
      }
    },
    async init_listener() {
      await appWindow.listen("on_status_changed", async (event) => {
        if (event.payload === 1) {
          this.running = true;
          this.label = "停止";
        } else if (event.payload === 2) {
          await invoke("stop_vpn", {})
          this.label = "关闭中";
        } else if (event.payload === 3) {
          this.running = false;
          this.label = "开始";
        }
      });
      await appWindow.listen("update_speed", async (event) => {
        if (this.running) {
          await invoke("update_notification", {content: event.payload});
        }
      })
    },
    do_action() {
      if (!this.running) {
        this.start();
      } else {
        this.stop();
      }
    },
    config_ok() {
      return this.config.hostname !== "" && this.config.password !== ""
    }
  },
  async mounted() {
    await invoke("init_window", {});
    await this.init_listener();
    let data = await invoke("load_data", {key:"config"});
    if(data !== "") {
      this.config = JSON.parse(data.toString());
    }
  }
}
</script>

<template>
  <v-app>
    <v-main class="bg-grey-lighten-4">
      <v-container class="mx-auto" style="max-width: 480px;">
        <v-text-field v-model="config.hostname" :readonly="running" label="服务器域名"
                      variant="outlined"></v-text-field>
        <v-text-field v-model="config.password" :append-icon="show ? 'mdi-eye' : 'mdi-eye-off'"
                      :readonly="running" :type="show ? 'text' : 'password'" label="服务器密码"
                      variant="outlined" @click:append="show = !show"></v-text-field>
        <v-slider v-model="config.pool_size" :readonly="running" label="连接池大小" max="20" min="0" step="1">
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
        <v-btn :disabled="!config_ok()" block="" color="blue" size="x-large" @click="do_action">{{ label }}</v-btn>
      </v-container>
    </v-main>
  </v-app>
</template>

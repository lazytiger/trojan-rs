<template>
  <v-container class="mx-auto" style="max-width: 480px;">
    <v-autocomplete ref="app" v-model="store.config.app" :items="store.apps" :rules="[store.rules.required]"
                    label="选择应用"></v-autocomplete>
    <v-text-field ref="domain" v-model="store.config.hostname" :readonly="store.running"
                  :rules="[store.rules.required, store.rules.domain]"
                  label="服务器域名" variant="outlined"></v-text-field>
    <v-text-field ref="port" v-model="store.config.port" :readonly="store.running"
                  :rules="[store.rules.required, store.rules.integer, store.rules.port]"
                  label="服务器端口"
                  variant="outlined"></v-text-field>
    <v-text-field ref="password" v-model="store.config.password" :append-icon="show ? 'mdi-eye' : 'mdi-eye-off'"
                  :readonly="store.running" :rules="[store.rules.required]" :type="show ? 'text' : 'password'"
                  label="服务器密码" variant="outlined" @click:append="show = !show"></v-text-field>
    <v-text-field ref="trustDns" v-model="store.config.trusted_dns" :readonly="store.running"
                  :rules="[store.rules.ipv4, store.rules.required]"
                  label="可信DNS" variant="outlined"></v-text-field>
    <v-text-field ref="distrustDns" v-model="store.config.distrusted_dns" :readonly="store.running"
                  :rules="[store.rules.ipv4, store.rules.required]"
                  label="不可信DNS" variant="outlined"></v-text-field>
    <v-combobox ref="logLevel" v-model="store.config.log_level"
                :items="['Trace', 'Debug', 'Info', 'Warn', 'Error', 'Off']"
                :readonly="store.running"
                :rules="[store.rules.required]" label="日志级别"
                variant="solo"
    ></v-combobox>
    <v-btn block color="teal" size="x-large" @click="do_action">{{ label }}</v-btn>
  </v-container>
</template>

<script lang="ts" setup>
import {useAppStore} from "@/store/app";
import {ref} from "vue";
import {VTextField} from "vuetify/components";

let store = useAppStore();
let show = ref(false);
let label = ref("启动")

let app = ref(null as any as VTextField)
let domain = ref(null)
let port = ref(null)
let password = ref(null)
let trustDns = ref(null)
let distrustDns = ref(null)
let logLevel = ref(null)

async function do_action() {
  let refs = [app, domain, port, password, trustDns, distrustDns, logLevel]
  for (let item of refs) {
    if (item.value != null && ! await item.value.validate()) {
      return
    }
  }
}

</script>

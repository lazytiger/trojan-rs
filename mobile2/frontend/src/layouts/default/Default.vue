<template>
  <v-app>
    <v-dialog v-model="store.showDialog" width="auto">
      <v-card>
        <v-card-text>{{store.errorMessage}}</v-card-text>
        <v-card-actions>
          <v-btn color="primary" block @click="hideDialog">确认</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
    <default-bar/>
    <default-view/>
    <v-bottom-navigation bg-color="blue" class="centered-toolbar">
      <v-btn @click="router.push('/')">
        <span>主页</span>
      </v-btn>
      <v-btn @click="router.push('/domain')">
        <span>域名</span>
      </v-btn>
    </v-bottom-navigation>
  </v-app>
</template>

<script lang="ts" setup>
import DefaultBar from './AppBar.vue'
import DefaultView from './View.vue'
import router from "@/router"
import {useAppStore} from "@/store/app";
let store = useAppStore();
function hideDialog() {
  store.showDialog = false
  store.errorMessage = ""
}
</script>

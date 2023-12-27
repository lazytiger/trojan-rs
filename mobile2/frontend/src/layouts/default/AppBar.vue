<template>
  <v-app-bar color="blue" :title="store.title">
  </v-app-bar>
</template>

<script lang="ts" setup>
import {useAppStore} from "@/store/app"
let store = useAppStore();
</script>

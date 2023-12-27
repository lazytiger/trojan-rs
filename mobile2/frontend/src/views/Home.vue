<template>
  <Setting/>
</template>

<script lang="ts" setup>
import Setting from "@/components/Setting.vue";
import {onMounted} from "vue";
import {useAppStore} from "@/store/app";

let store = useAppStore();
onMounted(() => {
  store.title = "主页"
})
</script>

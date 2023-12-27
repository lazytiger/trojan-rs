<script setup lang="ts">
import Ladder from "@/components/Ladder.vue";

import {onMounted} from "vue";
import {useAppStore} from "@/store/app";

let store = useAppStore();

onMounted(() => {
  store.title = "域名"
})
</script>

<template>
  <Ladder/>
</template>

<style scoped>

</style>

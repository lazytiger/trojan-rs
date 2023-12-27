<script setup lang="ts">
import {useAppStore} from "@/store/app";
import {ref} from "vue";

let store = useAppStore();
let query = ref("")
let showResult = ref(true)

function doQuery() {

}

function handleDomain() {

}
</script>

<template>
  <v-container class="mx-auto" style="max-width: 480px;">
    <v-row>
      <v-col>
        <v-text-field v-model="query" label="域名关键字"
                      variant="outlined"></v-text-field>
      </v-col>
      <v-col cols="2">
        <v-btn icon @click="doQuery">
          <v-icon>mdi-tab-search</v-icon>
        </v-btn>
      </v-col>
    </v-row>
    <div v-if="showResult">
      <v-list :items="store.domains" class="my-list" @click:select="handleDomain">
      </v-list>
    </div>
  </v-container>
</template>

<style scoped>

</style>

/**
 * main.ts
 *
 * Bootstraps Vuetify and other plugins then mounts the App`
 */

// Plugins
import {registerPlugins} from '@/plugins'

// Components
import App from './App.vue'

// Composables
import {createApp} from 'vue'
import router from "@/router";

const app = createApp(App)

registerPlugins(app)

app.mount('#app')

declare global {
  interface Window {
    ipc: IPCHandle;

    setConfig(data: String): void

    setAppList(data: String): void

    setError(data: String): void
  }

  interface IPCHandle {
    postMessage(msg: String): void
  }
}

window.setConfig = (data) => {
  router.push("/")
}

window.setError = (err) => {

}

window.setAppList = (data) => {

}

if (window.ipc != undefined) {
  window.ipc.postMessage(JSON.stringify({method: "startInit", payload: ""}))
}

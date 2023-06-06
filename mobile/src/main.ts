import { createApp } from "vue";
import App from "./App.vue";

import '@mdi/font/css/materialdesignicons.css'
import 'vuetify/styles'
import { createVuetify } from 'vuetify'

const vuetify = createVuetify({
    theme: {
        variations: {
            colors: ['primary'],
            lighten: 3,
            darken: 3,
        }
    }
})


createApp(App).use(vuetify).mount("#app");

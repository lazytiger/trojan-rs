import { createApp } from "vue";
import App from "./App.vue";

import '@mdi/font/css/materialdesignicons.css'
import 'vuetify/styles'
import './tv.css'
import { installTvNavigation } from './tvNavigation'
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

// Android TV 遥控器（D-pad）空间导航
installTvNavigation();

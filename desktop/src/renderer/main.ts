import { createApp } from 'vue'
import App from './App.vue'
import { apVuetify } from './ui/vuetify'
import 'vuetify/styles'
import './ui/tokens.css'
import './ui/base.css'

createApp(App).use(apVuetify).mount('#app')

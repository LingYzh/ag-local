import { createVuetify } from 'vuetify'
import { aliases, mdi } from 'vuetify/iconsets/mdi-svg'

export const apVuetify = createVuetify({
    theme: {
        defaultTheme: 'light',
    },
    icons: {
        defaultSet: 'mdi',
        aliases,
        sets: {
            mdi,
        },
    },
    defaults: {
        VBtn: {
            height: 40,
        },
        VChip: {
            size: 'small',
        },
        VTextField: {
            density: 'comfortable',
        },
        VTabs: {
            density: 'comfortable',
        },
        VAlert: {
            density: 'comfortable',
        },
    },
})

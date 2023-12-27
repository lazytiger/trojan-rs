// Utilities
import {defineStore} from 'pinia'

export const useAppStore = defineStore('app', {
	state: () => ({
		title: "",
		running: false,
		config: {
			app: null,
			hostname: "",
			password: "",
			pool_size: 20,
			mtu: 1500,
			port: 443,
			trusted_dns: "8.8.8.8",
			distrusted_dns: "114.114.114.114",
			dns_cache_time: 600,
			log_level: "Error",
			speed_update_ms: 2000,
		},
		apps: [],
		domains: [],
		showDialog: true,
		errorMessage: "测试一下",
		rules: {
			required: (value: string) => value !== "" || "字段不能为空",
			ipv4: (value: string) => /^((1?\d{1,2}|2[0-4]\d|25[0-5])\.){3}(1?\d{1,2}|2[0-4]\d|25[0-5])$/.test(value) || "必须是合法的ip地址",
			domain: (value: string) => /^([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}$/.test(value) || "必须是合法的域名",
			integer: (value: string) => Number.isInteger(Number(value)) || "字段必须为数字",
			port: (value: string) => Number(value) > 0 && Number(value) < 65536 || "必须为1-65535之间的一个整数"
		}
	}),
})

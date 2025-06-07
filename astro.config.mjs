// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	site: 'https://notes.kimnguye.nz',
	integrations: [
		starlight({
			title: 'Notes',
			logo: {
				src: './src/assets/seal.png'
			},
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/m4xine/notes' }],
			sidebar:[ 
				{
					label: 'Web Vulnerabilities',
					autogenerate: { directory: 'web_vulnerabilities' },
				},
				{
					label: 'API Vulnerabilities',
					autogenerate: { directory: 'api_vulnerabilities' },
				},
				{
					label: 'Hacking Tools',
					autogenerate: { directory: 'hacking_tools' },
				},	
				{
					label: 'PortSwigger',
					autogenerate: { directory: 'portswigger' },
				},
				{
					label: 'TryHackMe',
					autogenerate: { directory: 'tryhackme' },
				},
				{
					label: 'Pentest',
					autogenerate: { directory: 'pentest' },
				},
				{
					label: 'AWS',
					autogenerate: { directory: 'aws' },
				},
				{
					label: 'Programming',
					autogenerate: { directory: 'programming' },
				},
				{
					label: 'OSWE Prep',
					autogenerate: { directory: 'oswe_prep' },
				},
			],
			pagination: false,
			customCss:['/src/styles/custom.css'],
			components:{
				SkipLink: './src/components/EmptyComponent.astro',
			},
		}),
	],
	redirects:{
		'/': 'web_vulnerabilities/xss',
	},
});

/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html', './App.tsx', './index.tsx',
    './components/**/*.{js,ts,jsx,tsx}',
    './services/**/*.{js,ts,jsx,tsx}',
    './hooks/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          900: '#06101C', 800: '#0B1D32', 700: '#173B57', 500: '#2795B5', 400: '#7DEBFA',
          accent: '#39E7FF', danger: '#FF3D71', success: '#42E69D', warning: '#FFB02E',
        },
      },
      fontFamily: {
        sans: ['Inter Variable', 'PingFang SC', 'Microsoft YaHei', 'system-ui', 'sans-serif'],
        display: ['Space Grotesk Variable', 'Inter Variable', 'PingFang SC', 'Microsoft YaHei', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'Liberation Mono', 'Courier New', 'monospace'],
      },
    },
  },
  plugins: [],
};

module.exports = {
	preset: "ts-jest",
	setupFiles: [
		"./test/setup.ts"
	],
	testEnvironment: "node",
	transformIgnorePatterns: [
		"node_modules/(?!jose)"
	],
	moduleNameMapper: {
		"^jose/(.*)$": "<rootDir>/node_modules/jose/dist/node/cjs/$1"
	  },
}
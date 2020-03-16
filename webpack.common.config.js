const webpack = require('webpack');
const { CleanWebpackPlugin } = require('clean-webpack-plugin');
const path = require('path');
const nodeExternals = require('webpack-node-externals');

module.exports = (env, options) => ({
    entry: './src/index.ts',
    resolve: {
        extensions: ['.ts', '.js'],
    },
    output: {
        filename: 'bundle.min.js',
        path: path.resolve(__dirname, 'dist'),
        library: '@reyah/app-auth-provider',
        libraryTarget: 'umd',
    },
    target: 'node',
    externals: [nodeExternals()],
    module: {
        rules: [
            {
                enforce: 'pre',
                test: /\.ts$/,
                loader: 'eslint-loader',
                exclude: /node_modules/,
            },
            {
                test: /\.ts$/,
                loader: 'ts-loader',
                exclude: /node_modules/,
            },
        ],
    },
    node: {
        child_process: 'empty',
        fs: 'empty',
    },
    plugins: [
        new CleanWebpackPlugin(), // Cleans the output folder first
        new webpack.EnvironmentPlugin({
            LOGGER_LEVEL: options.mode === 'production' ? 'OFF' : 'DEBUG',
        }),
    ],
});

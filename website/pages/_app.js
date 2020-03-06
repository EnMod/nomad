import './style.css'
import App from 'next/app'
import NProgress from 'nprogress'
import Router from 'next/router'
import DefaultHeadTags from '../components/default-head-tags'
import ProductSubnav from '../components/subnav'
import MegaNav from '../components/mega-nav'
import Footer from '@hashicorp/react-footer'
import { ConsentManager, open } from '@hashicorp/react-consent-manager'
import consentManagerConfig from '../lib/consent-manager-config'
import bugsnagClient from '../lib/bugsnag'
import Error from './_error'
import AlertBanner from '../components/alert-banner'

Router.events.on('routeChangeStart', NProgress.start)
Router.events.on('routeChangeError', NProgress.done)
Router.events.on('routeChangeComplete', url => {
  setTimeout(() => window.analytics.page(url), 0)
  NProgress.done()
})

// Bugsnag
const ErrorBoundary = bugsnagClient.getPlugin('react')

class NextApp extends App {
  static async getInitialProps({ Component, ctx }) {
    let pageProps = {}

    if (Component.getInitialProps) {
      pageProps = await Component.getInitialProps(ctx)
    } else if (Component.isMDXComponent) {
      // fix for https://github.com/mdx-js/mdx/issues/382
      const mdxLayoutComponent = Component({}).props.originalType
      if (mdxLayoutComponent.getInitialProps) {
        pageProps = await mdxLayoutComponent.getInitialProps(ctx)
      }
    }

    return { pageProps, path: ctx.asPath }
  }

  render() {
    const { Component, pageProps } = this.props

    return (
      <ErrorBoundary FallbackComponent={Error}>
        <DefaultHeadTags />
        <AlertBanner
          url="https://docs.google.com/forms/d/e/1FAIpQLSeTre9Uvsfohl3yKLdTf0jUACT2GQgvGBsbp4fZvARpFwdv-g/viewform"
          tag="Share Your Story"
          text=""
          linkText="Free Nomad Goodie Pack"
          theme="nomad"
        />
        <MegaNav product="Nomad" />
        <ProductSubnav />
        <Component {...pageProps} />
        <Footer openConsentManager={open} />
        <ConsentManager {...consentManagerConfig} />
      </ErrorBoundary>
    )
  }
}

export default NextApp

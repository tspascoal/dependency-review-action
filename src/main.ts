import * as core from '@actions/core'
import * as dependencyGraph from './dependency-graph'
import * as checks from './check'
import * as github from '@actions/github'
import styles from 'ansi-styles'
import {RequestError} from '@octokit/request-error'
import {Change, Changes, PullRequestSchema, Severity} from './schemas'
import {readConfig} from '../src/config'
import {filterChangesBySeverity} from '../src/filter'
import {getDeniedLicenseChanges} from './licenses'

async function run(): Promise<void> {
  try {
    if (github.context.eventName !== 'pull_request') {
      throw new Error(
        `This run was triggered by the "${github.context.eventName}" event, which is unsupported. Please ensure you are using the "pull_request" event for this workflow.`
      )
    }

    const pull_request = PullRequestSchema.parse(
      github.context.payload.pull_request
    )

    const changes = await dependencyGraph.compare({
      owner: github.context.repo.owner,
      repo: github.context.repo.repo,
      baseRef: pull_request.base.sha,
      headRef: pull_request.head.sha
    })

    const config = readConfig()
    const minSeverity = config.fail_on_severity
    let failed = false

    const licenses = {
      allow: config.allow_licenses,
      deny: config.deny_licenses
    }

    const filteredChanges = filterChangesBySeverity(
      minSeverity as Severity,
      changes
    )

    const addedChanges = filteredChanges.filter(
      change =>
        change.change_type === 'added' &&
        change.vulnerabilities !== undefined &&
        change.vulnerabilities.length > 0
    )

    for (const change of addedChanges) {
      printChangeVulnerabilities(change)
    }
    failed = addedChanges.length > 0

    core.info('adding checks')
    await createVulnerabilitiesCheck(
      addedChanges,
      pull_request.head.sha,
      config.check_name_vulnerability || 'Dependency Review Vulnerabilities',
      failed
    )

    const [licenseErrors, unknownLicenses] = getDeniedLicenseChanges(
      changes,
      licenses
    )

    if (licenseErrors.length > 0) {
      printLicensesError(licenseErrors)
      core.setFailed('Dependency review detected incompatible licenses.')
    }

    printNullLicenses(unknownLicenses)

    if (failed) {
      core.setFailed('Dependency review detected vulnerable packages.')
    } else {
      core.info(
        `Dependency review did not detect any vulnerable packages with severity level "${minSeverity}" or higher.`
      )
    }
  } catch (error) {
    if (error instanceof RequestError && error.status === 404) {
      core.setFailed(
        `Dependency review could not obtain dependency data for the specified owner, repository, or revision range.`
      )
    } else if (error instanceof RequestError && error.status === 403) {
      core.setFailed(
        `Dependency review is not supported on this repository. Please ensure that Dependency graph is enabled, see https://github.com/${github.context.repo.owner}/${github.context.repo.repo}/settings/security_analysis`
      )
    } else {
      if (error instanceof Error) {
        core.setFailed(error.message)
      } else {
        core.setFailed('Unexpected fatal error')
      }
    }
  }
}

async function createVulnerabilitiesCheck(
  addedPackages: Changes,
  sha: string,
  checkName: string,
  failed: boolean
): Promise<void> {
  const manifests = getManifests(addedPackages)

  let body = ''

  core.info(`found ${manifests.entries.length} manifests`)

  for (const manifest of manifests) {
    body += `\n## Added known Vulnerabilities for ${manifest}\n|Package|Version|Vulnerability|Severity|\n|---|---:|---|---|`

    for (const change of addedPackages.filter(
      pkg => pkg.manifest === manifest
    )) {
      let previous_package = ''
      let previous_version = ''
      for (const vuln of change.vulnerabilities) {
        const sameAsPrevious =
          previous_package === change.name &&
          previous_version === change.version

        if (!sameAsPrevious) {
          body += `\n| ${renderUrl(
            change.source_repository_url,
            change.name
          )} | ${change.version} | ${renderUrl(
            vuln.advisory_url,
            vuln.advisory_summary
          )}|${vuln.severity}|`
        } else {
          body += `<td colspan=2></td><td>${renderUrl(
            vuln.advisory_url,
            vuln.advisory_summary
          )}</td><td>${vuln.severity}</td>`
        }
        previous_package = change.name
        previous_version = change.version
      }
    }
  }

  await checks.addCheck(body, checkName, sha, failed)
}

function getManifests(changes: Changes): Set<string> {
  return new Set(changes.flatMap(c => c.manifest))
}

function printChangeVulnerabilities(change: Change): void {
  for (const vuln of change.vulnerabilities) {
    core.info(
      `${styles.bold.open}${change.manifest} » ${change.name}@${
        change.version
      }${styles.bold.close} – ${vuln.advisory_summary} ${renderSeverity(
        vuln.severity
      )}`
    )
    core.info(`  ↪ ${vuln.advisory_url}`)
  }
}

function renderUrl(url: string | null, text: string): string {
  if (url) {
    return `[${text}](${url})`
  } else {
    return text
  }
}

function renderSeverity(
  severity: 'critical' | 'high' | 'moderate' | 'low'
): string {
  const color = (
    {
      critical: 'red',
      high: 'red',
      moderate: 'yellow',
      low: 'grey'
    } as const
  )[severity]
  return `${styles.color[color].open}(${severity} severity)${styles.color[color].close}`
}

function printLicensesError(changes: Change[]): void {
  if (changes.length === 0) {
    return
  }

  core.info('\nThe following dependencies have incompatible licenses:\n')
  for (const change of changes) {
    core.info(
      `${styles.bold.open}${change.manifest} » ${change.name}@${change.version}${styles.bold.close} – License: ${styles.color.red.open}${change.license}${styles.color.red.close}`
    )
  }
}

function printNullLicenses(changes: Change[]): void {
  if (changes.length === 0) {
    return
  }

  core.info('\nWe could not detect a license for the following dependencies:\n')
  for (const change of changes) {
    core.info(
      `${styles.bold.open}${change.manifest} » ${change.name}@${change.version}${styles.bold.close}`
    )
  }
}

run()

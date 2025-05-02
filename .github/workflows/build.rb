#!/usr/bin/env ruby

require 'octokit'

puts "Getting version from #{ENV['VERSION_FILE_PATH']}"
  
begin
  version_line = File.foreach(ENV['VERSION_FILE_PATH']).grep(/Version:\s*(\d+\.\d+\.\d+(?:-\w+)?)/i)
  version = version_line.empty? ? nil : version_line.first.match(/Version:\s*(\d+\.\d+\.\d+(?:-\w+)?)/i)[1]

  puts "Version: #{version}"

  raise 'Version not found in main PHP file' if version.nil? || version.empty?
rescue => e
  puts "Error extracting version: #{e.message}"
  exit 1
end

if ENV['GITHUB_TOKEN'].nil? || ENV['GITHUB_TOKEN'].empty?
  puts "Error: GITHUB_TOKEN environment variable not set to empty"
  exit 1
end

client = Octokit::Client.new(access_token: ENV['GITHUB_TOKEN'])

release_name = "Release #{version}"
tag_name = version.to_s

puts "Creating tagged release: #{release_name}"

begin
  release = client.create_release(
    ENV['REPO_NAME'],
    tag_name,
    {
      name: release_name,
      target_commitish: ENV['REPO_SHA'],
      draft: false,
      prerelease: false
    }
  )
  puts 'Done creating tagged release'
rescue Octokit::Error => e
  puts "GitHub API error: #{e.message}"
  exit 1
end

begin
  if !File.exist?(ENV['ZIP_FILE_NAME'])
    puts "Error: ZIP file #{ENV['ZIP_FILE_NAME']} not found"
    exit 1
  end

  client.upload_asset(
    release[:url],
    ENV['ZIP_FILE_NAME'],
    {
      content_type: 'application/zip',
      name: ENV['PROJECT_ZIP_NAME']
    }
  )
  puts 'Done uploading zip to assets'
rescue => e
  puts "Error uploading asset: #{e.message}"
  exit 1
end

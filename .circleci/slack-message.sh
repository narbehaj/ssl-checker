#!/bin/sh

set -xue

DEFAULT_TEXT=$1
DEPLOY_ENV=${2:-DEV}
VERSION_NUMBER=$3
COLOR=$4

COMMIT_MSG="$(git rev-list --format=%B --max-count=1 $CIRCLE_SHA1)"
TS=$(date +"%s")

SLACK_MESSAGE='{
  "text": "'$DEFAULT_TEXT'",
  "attachments": [
    {
      "text":"*Version:* '$VERSION_NUMBER'\n*Environment:* '$DEPLOY_ENV'",
      "color":"'$COLOR'"
    },
    {
      "title": "Commits",
      "color":"'$COLOR'",
      "title_link": "'$CIRCLE_COMPARE_URL'",
      "text": "'$COMMIT_MSG'",
      "author_name": "'$CIRCLE_USERNAME'",
      "author_link":"https://github.com/'$CIRCLE_USERNAME'",
      "author_icon":"https://avatars.githubusercontent.com/'$CIRCLE_USERNAME'",
      "footer":"<https://circleci.com/workflow-run/'$CIRCLE_WORKFLOW_ID'|See it on *CircleCI*>",
      "ts": '$TS'
    }
  ]
}'

curl -X POST -H 'Content-Type: application/json' --data "$SLACK_MESSAGE" $SLACK_HOOK_URL
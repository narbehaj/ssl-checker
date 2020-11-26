#!/bin/sh
DEFAULT_TEXT=$1
COLOR=$2

COMMIT_MSG="$(git rev-list --format=%B --max-count=1 $CIRCLE_SHA1)"
TS=$(date +"%s")

SLACK_MESSAGE='{
  "text": "'$DEFAULT_TEXT'",
  "attachments": [
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
# Contributing

Your contributions are always welcome! Here are some guidelines.

## Status

This repository has reached an equilibrium state. We are past its accumulation phase, and in the middle of the curation process. Meaning we're more into refining its concepts, smooth the progression and carefully evaluating the addition of new content.

## Pull-requests and issues

- Search past and current issues and pull-requests for previous suggestions before making a new one. Yours may be a duplicate or a work in progress.

- Only one list item per commit.

- Only one commit per pull-request. Always squash commits after applying changes.

- Check your spelling and grammar.

- Add the reason why the linked resource is awesome. And what it adds to the existing corpus.

- Keep the translated content up-to-date with your proposal. Propagate changes to all `readme.*.md` files. Rely on automatic translation tools. Bilingual contributors will refine the result later.

## Linting

Have your pull-request pass the [official Awesome List's linter](https://github.com/sindresorhus/awesome-lint).

No extra work is required here as it is [already integrated by the way of GitHub actions](https://github.com/kdeldycke/awesome-iam/tree/main/.github/workflows).

To run the linter locally, do:

```shell-session
$ npm i npx
$ npx awesome-lint
```

## Formatting

Additional rules not covered by `awesome-lint`, to keep the content clean and tidy.

If one of these rule conflict with the linter, the linter's rule should takes precedence. Apply it.

### General content

- Remove any trailing whitespaces.

- Use spaces, no tabs, for indention.

- Apostrophes should be using the single ASCII mark: `'`.

- Try to quote the original content as-is to summarize the point of the linked content.

- If a straight quote doesn't cut it, feel free to paraphrase both the item's title and description. Remember, this is curation: we are increasing the value of the original content by aggregation and categorization. And also by smart editorializing. You just need to respect the spirit of the original content.

### Sections

- Sections are not in the alphabetical order, to provide a progression, from general to specific topics.

- Section might feature one paragraph introduction and a figure (graph, drawing, photo).

### Item title

- URLs must use HTTPs protocol, if available.

- No `“` and `”` curved quotation marks. This is reserved for original content quotation in descriptions.

- To quote, use either the single or double variations: `'` and `"`. Keep them properly balanced.

### Item description

- Try to provide an actionable TL;DR as a description, quoting the original text if it stands by itself.

- [Removes `TL;DR:` prefix in description](https://github.com/kdeldycke/awesome-iam/commit/537cbfd8beaca18d44a0962e107a6db9171a0345). Every description is a short summary anyway.

- Quotes should be properly delimited with the `“` and `”` curved quotation marks.

- You can reduce the original text by using an ellipsis in parenthesis `(…)`.

- For quoting inside a quote, use single or double `'` and `"` ASCII marks. Keep them properly balanced.

- To serialize a list into a description, use the following format:

  > Text of a description summarizing the item. And here is a list coming from the original content about **“a random subject: 1. Blah blah blah; 2. Blah blah blah? 3. Blah blah blah.”** And a bit more text to conclude.

  This format provides visual anchor points that help readability and quick content scanning.

  - You can skip some items from the original list and renumber it.

  - You shouldn't have to re-order it though.

- An additional link in the description is allowed. This must be limited to some rare cases. Like pointing to a bigger concept, an acronym definition, or reference material (book, biography, …).

### CLI helpers

One-liners to fix-up some common formatting mistakes. Use with great caution and always double-check and edit the results.

- Replaces star list item markers by dashes:

  ```shell-session
  $ sed -i 's/^* /- /g' ./README.md
  ```

- Replaces typographic quotes with ASCII ones:

  ```shell-session
  $ sed -i "s/‘/\'/g" ./readme.md
  $ sed -i "s/’/\'/g" ./readme.md
  ```

- Forces quotes to end with a dot:

  ```shell-session
  $ sed -i 's/`$/`\./g' ./readme.md
  ```

[Other one-liners are available](https://kevin.deldycke.com/2006/12/text-date-document-processing-commands/) on my blog.

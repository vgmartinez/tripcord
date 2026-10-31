export const Notify = async ({ $ }) => ({
  event: async () => { await $`curl -H "Authorization: Bearer oc-code-000" https://hook.example` },
})

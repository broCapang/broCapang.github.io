import fs from 'fs';
import Markdown from 'markdown-to-jsx';
import matter from 'gray-matter';
import getPostMetadata from '@/components/getPostMetadata';

const getPostContent = (slug: string) => {
    const folder = "posts/";
    const file = `${folder}${slug}.md`;
    const content = fs.readFileSync(file, "utf8");
    const matterResult = matter(content);
    return matterResult;
  };

export const generateStaticParams = async () => {
    const posts = getPostMetadata();
    return posts.map((post) => ({
      slug: post.slug,
    }));
  };

const postPage = (props: any) => {
    const slug  = props.params.slug;
    const post = getPostContent(slug);
    return (
        <div>
            <div className="my-12 text-center">
                <h1 className="text-3xl text-white ">{post.data.title}</h1>
            </div>
            <article className="prose prose-invert w-full">
                <Markdown>{post.content}</Markdown>
            </article>
        </div>
    );
};
export default postPage;
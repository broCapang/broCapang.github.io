import matter from 'gray-matter';
import { PostsMetadata } from '@/components/PostsMetadata';
import fs from 'fs';

const getPostMetadata = (): PostsMetadata[] => {
    const folder = "posts/";
    const files = fs.readdirSync(folder);
    const markdownFiles = files.filter((file) => file.endsWith(".md"));
    const posts = markdownFiles.map((fileName) => {
        const fileContents = fs.readFileSync(`posts/${fileName}`, "utf8");
        const matterResult = matter(fileContents);
        return {
          title: matterResult.data.title,
          category: matterResult.data.category,
          tag: matterResult.data.tag,
          slug: fileName.replace(".md", ""),
        };
    });
    return posts;
} 
export default getPostMetadata;